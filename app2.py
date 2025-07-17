#Create a New User
#Add a book with no. copies , author, book name
#get all books unique books ,
#

import os
import datetime
import time
from flask import Flask, request, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import and_, any_, case, func
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, insert
from flask_bcrypt import Bcrypt
from flask_cors import CORS
import urllib.parse
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    jwt_required,
    get_jwt_identity,
    get_jwt,
)
from werkzeug.utils import secure_filename
import pytz
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import joinedload
from sqlalchemy import Enum
from dateutil import parser
from sqlalchemy.orm import aliased
# Initialize app
app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": ["/","http://localhost:5173", "https://my-app.com"]}})

# CORS(app, resources={r"/api/*": {"origins": "*"}})

password = urllib.parse.quote_plus('pgAdmin@4')
POSTGRES_URL= 'localhost:5432'
POSTGRES_USER= 'postgres'
POSTGRES_PW = password
POSTGRES_DB = 'bookstoredb'
app.config['SQLALCHEMY_DATABASE_URI']='postgresql+psycopg2://{user}:{pw}@{url}/{db}'.format(user=POSTGRES_USER,pw=POSTGRES_PW,url=POSTGRES_URL,db=POSTGRES_DB)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'ZZFLcC15_2ecErW6'
app.config['JWT_SECRET_KEY'] = 'ZZFLcC15_2ecErW6'


db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

def current_utc_time():
    return datetime.datetime.now(datetime.timezone.utc)
#db models
import enum

class UserRole(enum.Enum):
    ADMIN = "admin"
    SELLER = "seller"
    USER = "user"

from sqlalchemy import Enum as PgEnum

class user(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=current_utc_time)
    role = db.Column(PgEnum(UserRole), nullable=False, default=UserRole.USER)

class book(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    author = db.Column(db.String(100), nullable=False)
    title = db.Column(db.String(100), unique=True, nullable=False)

class seller(db.Model):
    id = db.Column(db.Integer, db.ForeignKey('user.id'), primary_key=True)
    book_id = db.Column(db.Integer, db.ForeignKey('book.id'), primary_key=True)
    price = db.Column(db.Integer, nullable=False)  # Buy price
    rent_price = db.Column(db.Integer, nullable=False)  # Rent price
    qty = db.Column(db.Integer, nullable=False)  # Available for rent or buy

    __table_args__ = (
        db.UniqueConstraint('id', 'book_id', name='uix_seller_book'),
    )

class rental(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    seller_id = db.Column(db.Integer, nullable=False)  # References seller.id
    book_id = db.Column(db.Integer, db.ForeignKey('book.id'), nullable=False)
    rented_qty = db.Column(db.Integer, nullable=False)
    rented_price = db.Column(db.Integer, nullable=False)
    rented_on = db.Column(db.DateTime(timezone=True), default=current_utc_time)
    return_by = db.Column(db.DateTime(timezone=True), nullable=False)  # Deadline
    returned_on = db.Column(db.DateTime(timezone=True), nullable=True)  # If null, book is not yet returned

    __table_args__ = (
        db.ForeignKeyConstraint(
            ['seller_id', 'book_id'],
            ['seller.id', 'seller.book_id']
        ),
    )

class purchase(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    seller_id = db.Column(db.Integer, nullable=False)
    book_id = db.Column(db.Integer, db.ForeignKey('book.id'), nullable=False)
    bought_qty = db.Column(db.Integer, nullable=False)
    bought_price = db.Column(db.Integer, nullable=False)
    bought_on = db.Column(db.DateTime(timezone=True), default=current_utc_time)

    __table_args__ = (
        db.ForeignKeyConstraint(
            ['seller_id', 'book_id'],
            ['seller.id', 'seller.book_id']
        ),
    )



# with app.app_context():
#     db.create_all()

def set_password(password):
    """Hashes and sets the user's password."""
    password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
    return password_hash

with app.app_context():
    db.create_all()

    try:
        def create_default_user(name, email, password, role):
            if not user.query.filter_by(email=email).first():
                password_hash = set_password(password)
                default_user = user(
                    name=name,
                    email=email,
                    password_hash=password_hash,
                    role=role
                )
                db.session.add(default_user)
                print(f"✅ Created default user: {email} ({role.value})")
            else:
                print(f"ℹ️ User already exists: {email}")

        # Create default recruiter (SELLER)
        create_default_user(
            name="Recruiter Seller",
            email="recruiter@example.com",
            password="recruiter123",
            role=UserRole.SELLER
        )

        # Create default regular user (USER)
        create_default_user(
            name="Test User",
            email="user@example.com",
            password="user123",
            role=UserRole.USER
        )

        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"❌ Error while creating default users: {str(e)}")


#Endpoints:

def set_password(password):
    """Hashes and sets the user's password."""
    password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
    return password_hash




#create new users:
@app.route('/api/register_seller', methods=['POST'])
def register_seller():
    return create_user(UserRole.SELLER)

#create new users:
@app.route('/api/register_user', methods=['POST'])
def register_user():
    return create_user(UserRole.USER)

def create_user(role):
    try:
        data = request.json
        name = data.get('name')
        email = data.get('email')
        password = data.get('password')
        
        password_hash = set_password(password)
        if user.query.filter_by(email=email).first():
            return jsonify({"error": "Email already exists"}), 409
        new_user = user(name=name, email=email, password_hash=password_hash, created_at=current_utc_time(), role=role)
        db.session.add(new_user)
        db.session.commit()
        return jsonify({"message":  "registered successfully"}), 201
    except Exception as ex:
        print(ex)
        return jsonify({"error": "Invalid email or password"}), 500
    
@app.route('/api/login/seller', methods=['POST'])
def login_seller():
    return get_user(UserRole.SELLER)

@app.route('/api/login/user', methods=['POST'])
def login_user():
    return get_user(UserRole.USER)

def get_user(expected_role):
    try:
        data = request.json
        email = data.get('email')
        password = data.get('password')
        found_user = user.query.filter_by(email=email).first()
        if found_user and bcrypt.check_password_hash(found_user.password_hash, password):
            if found_user.role != expected_role:
                return jsonify({"error": f"Not a {expected_role.value} account"}), 403
            access_token = create_access_token(identity=email)
            return jsonify({"message": "Login successful", "access_token": access_token}), 200
        return jsonify({"error": "Invalid credentials"}), 401
    except Exception as ex:
        print(ex)
        return jsonify({"error": "Invalid email or password"}), 401
    
@app.route('/api/verify_token', methods=['GET'])
@jwt_required()
def verify_token():
    try:
        user_email = get_jwt_identity()
        found_user = user.query.filter_by(email=user_email).first()
        if found_user:
            return jsonify({
                "valid": True,
                "email": found_user.email,
                "role": found_user.role.value,
                "name": found_user.name
            }), 200
        return jsonify({"valid": False}), 401
    except Exception as e:
        return jsonify({"valid": False, "error": str(e)}), 401


#create books api:

@app.route('/api/add_book', methods=['POST'])
@jwt_required()
def add_book():
    try:
        user_email = get_jwt_identity()
        seller_user = user.query.filter_by(email=user_email).first()

        if not seller_user or seller_user.role != UserRole.SELLER:
            return jsonify({"error": "Only sellers can add books"}), 403

        data = request.json
        title = data.get("title", "").strip()
        author = data.get("author", "").strip()
        price = data.get("price")
        rent_price = data.get("rent_price")
        qty = data.get("qty")

        if not title or not author or price is None or rent_price is None or qty is None:
            return jsonify({"error": "Missing required fields"}), 400

        # Step 1: Check if the book already exists by title (you could add author match too if needed)
        existing_book = book.query.filter_by(title=title).first()
        if not existing_book:
            # Create new book
            existing_book = book(title=title, author=author)
            db.session.add(existing_book)
            db.session.flush()  # So book.id becomes available without committing yet

        # Step 2: Check if this seller already listed this book
        existing_seller_entry = seller.query.filter_by(id=seller_user.id, book_id=existing_book.id).first()
        if existing_seller_entry:
            # Update existing seller entry
            existing_seller_entry.price = price
            existing_seller_entry.rent_price = rent_price
            existing_seller_entry.qty = qty
        else:
            # Create new seller-book association
            new_seller_entry = seller(
                id=seller_user.id,
                book_id=existing_book.id,
                price=price,
                rent_price=rent_price,
                qty=qty
            )
            db.session.add(new_seller_entry)

        db.session.commit()

        return jsonify({
            "message": "Book added/updated for seller successfully",
            "book_id": existing_book.id,
            "title": existing_book.title
        }), 201

    except Exception as ex:
        print(ex)
        db.session.rollback()
        return jsonify({"error": str(ex)}), 500


@app.route('/api/update_book/<int:book_id>', methods=['PUT'])
@jwt_required()
def update_book(book_id):
    try:
        # Identify the logged-in seller
        user_email = get_jwt_identity()
        seller_user = user.query.filter_by(email=user_email).first()

        if not seller_user or seller_user.role != UserRole.SELLER:
            return jsonify({"error": "Only sellers can update books"}), 403

        # Extract new data from request
        data = request.get_json()
        price = data.get("price")
        rent_price = data.get("rent_price")
        qty = data.get("qty")
        
        if price is None or rent_price is None or qty is None:
            return jsonify({"error": "Missing required fields"}), 400

        # Verify that the book exists
        existing_book = book.query.get(book_id)
        if not existing_book:
            return jsonify({"error": "Book not found"}), 404

        # Check if the seller owns this listing
        seller_entry = seller.query.filter_by(id=seller_user.id, book_id=book_id).first()
        if not seller_entry:
            return jsonify({"error": "This book is not listed by you"}), 403

        # Update seller-specific book info
        seller_entry.price = price
        seller_entry.rent_price = rent_price
        seller_entry.qty = qty

        db.session.commit()

        return jsonify({
            "message": "Book listing updated successfully",
            "book_id": book_id,
            "seller_id": seller_user.id,
            "title": existing_book.title
        }), 200

    except Exception as ex:
        print(f"Error in update_book: {ex}")
        db.session.rollback()
        return jsonify({"error": "Internal Server Error"}), 500





@app.route('/api/list_books', methods=['GET'])
@jwt_required()
def get_books():
    try:
        page = int(request.args.get('page', 1))
        limit = int(request.args.get('limit', 10))
        offset = (page - 1) * limit

        user_email = get_jwt_identity()
        user_data = user.query.filter_by(email=user_email).first()
        if not user_data:
            return jsonify({"error": "Invalid token or user not found"}), 401

        # Get books with at least one seller having qty > 0
        books_with_sellers = (
            db.session.query(
                book.id.label("book_id"),
                book.title,
                book.author,
                seller.id.label("seller_id"),
                user.name.label("seller_name"),
                user.email.label("seller_email"),
                seller.price.label("buy_price"),
                seller.rent_price,
                seller.qty.label("available_qty")
            )
            .join(seller, book.id == seller.book_id)
            .join(user, seller.id == user.id)
            .filter(seller.qty > 0)
            .order_by(book.title)
            .offset(offset)
            .limit(limit)
            .all()
        )

        has_more = len(books_with_sellers) == limit

        # Format the response
        books_dict = {}
        for entry in books_with_sellers:
            key = (entry.book_id, entry.title, entry.author)
            if key not in books_dict:
                books_dict[key] = []
            books_dict[key].append({
                "seller_id": entry.seller_id,
                "seller_name": entry.seller_name,
                "seller_email": entry.seller_email,
                "buy_price": entry.buy_price,
                "rent_price": entry.rent_price,
                "available_qty": entry.available_qty
            })

        result = []
        for (book_id, title, author), sellers in books_dict.items():
            result.append({
                "book_id": book_id,
                "title": title,
                "author": author,
                "available_from": sellers
            })

        return jsonify({
            "books": result,
            "has_more": has_more
        }), 200

    except Exception as ex:
        print("Error in /api/list_books:", ex)
        db.session.rollback()
        return jsonify({"error": str(ex)}), 500



@app.route('/api/book_availability/<int:book_id>', methods=['GET'])
@jwt_required()
def book_availability(book_id):
    try:
        user_email = get_jwt_identity()
        user_data = user.query.filter_by(email=user_email).first()
        if not user_data:
            return jsonify({"error": "Invalid token or user not found"}), 401

        book_details = book.query.filter_by(id=book_id).first()
        if not book_details:
            return jsonify({"error": "Book not found"}), 404

        # Fetch current available seller data
        availability_data = db.session.query(
            seller.id.label("seller_id"),
            user.name.label("seller_name"),
            seller.price.label("buy_price"),
            seller.rent_price,
            seller.qty.label("available_qty")
        ).join(user, user.id == seller.id) \
         .filter(seller.book_id == book_id) \
         .all()

        result = []
        for s in availability_data:
            result.append({
                "seller_id": s.seller_id,
                "seller_name": s.seller_name,
                "buy_price": s.buy_price,
                "rent_price": s.rent_price,
                "available_qty": int(s.available_qty)
            })

        return jsonify(result), 200

    except Exception as ex:
        print("Error:", ex)
        db.session.rollback()
        return jsonify({"error": str(ex)}), 500



@app.route('/api/buy_book', methods=['POST'])
@jwt_required()
def buy_book():
    try:
        user_email = get_jwt_identity()
        user_data = user.query.filter_by(email=user_email).first()
        if not user_data:
            return jsonify({"error": "Invalid token or user not found"}), 401
        data = request.get_json()
        seller_id = data['seller_id']
        book_id = data['book_id']
        qty = int(data['qty'])
        if qty < 1:
            return jsonify({'error': 'Quantity must be at least 1'}), 400

        s = seller.query.filter_by(id=seller_id, book_id=book_id).first()
        if not s:
            return jsonify({'error': 'Seller not found'}), 404

        if s.qty < qty:
            return jsonify({'error': 'Not enough quantity available'}), 400

        # Deduct purchased quantity from seller's stock
        s.qty -= qty
        db.session.commit()

        # Add purchase record
        p = purchase(
            user_id=user_data.id,
            seller_id=seller_id,
            book_id=book_id,
            bought_qty=qty,
            bought_price=s.price * qty,  # Assuming the price is per book
            bought_on=datetime.datetime.utcnow()
        )
        db.session.add(p)
        db.session.commit()

        return jsonify({'message': f'Successfully bought {qty} book(s)'}), 200

    except SQLAlchemyError as e:
        print(e,"sql")
        db.session.rollback()
        return jsonify({'error': str(e)}), 500
    except Exception as e:
        print(e,"normal")
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/api/rent_book', methods=['POST'])
@jwt_required()
def rent_book():
    try:
        user_email = get_jwt_identity()
        user_data = user.query.filter_by(email=user_email).first()
        if not user_data:
            return jsonify({"error": "Invalid token or user not found"}), 401
        data = request.get_json()
        seller_id = data['seller_id']
        book_id = data['book_id']
        qty = int(data['qty'])
        return_by_str = data['return_by']

        if qty < 1:
            return jsonify({'error': 'Quantity must be at least 1'}), 400

        return_by = parser.parse(return_by_str)
        if return_by <= datetime.datetime.utcnow():
            return jsonify({'error': 'Return date must be in the future'}), 400
        print(seller_id,book_id,qty)
        s = seller.query.filter_by(id=seller_id, book_id=book_id).first()
        print(s.qty)
        if not s:
            return jsonify({'error': 'Seller not found'}), 404

        if s.qty < qty:
            return jsonify({'error': 'Not enough quantity available'}), 400

        # Decrease available quantity
        s.qty -= qty
        print(s.qty)
        # Create rental record
        r = rental(
            user_id=user_data.id,
            seller_id=seller_id,
            book_id=book_id,
            rented_qty=qty,
            rented_price=s.rent_price * qty,
            rented_on=datetime.datetime.utcnow(),
            return_by=return_by
        )
        print(r)
        db.session.add(r)
        db.session.commit()

        return jsonify({'message': f'Rented {qty} book(s) until {return_by.date()}'}), 200

    except SQLAlchemyError as e:
        print(e,"sql")
        db.session.rollback()
        return jsonify({'error': str(e)}), 500
    except Exception as e:
        print(e,"normal")
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


@app.route('/api/purchased_books', methods=['GET'])
@jwt_required()
def get_purchased_books():
    try:
        # Get the user's email from the JWT token and fetch the user data
        user_email = get_jwt_identity()
        user_data = user.query.filter_by(email=user_email).first()

        if not user_data:
            return jsonify({"error": "User not found"}), 404

        # Query the purchased books for the logged-in user, ensuring no duplicates
        purchased_books = db.session.query(purchase, book, seller, user) \
            .join(book, purchase.book_id == book.id) \
            .join(seller, purchase.seller_id == seller.id) \
            .join(user, seller.id == user.id) \
            .filter(purchase.user_id == user_data.id) \
            .distinct(purchase.id) \
            .all()

        # Prepare the response data by extracting relevant details
        purchased_books_list = [
            {
                'purchase_id': purchase.id,
                'book_title': book.title,
                'book_author': book.author,
                'bought_qty': purchase.bought_qty,
                'bought_price': purchase.bought_price,
                'bought_on': purchase.bought_on,
                'seller_name': user.name,
            }
            for purchase, book, seller, user in purchased_books
        ]
        return jsonify(purchased_books_list), 200

    except Exception as e:
        print(e)
        return jsonify({'error': str(e)}), 500




@app.route('/api/rented_books', methods=['GET'])
@jwt_required()
def get_rented_books():
    try:
        user_email = get_jwt_identity()
        user_data = user.query.filter_by(email=user_email).first()

        if not user_data:
            return jsonify({"error": "Invalid token or user not found"}), 401

        # Create alias for seller user
        seller_user = aliased(user)

        # Join rental → book → seller → seller_user (who is the seller of the book)
        rented_books = (
            db.session.query(
                rental.id.label("rental_id"),
                rental.rented_qty,
                rental.rented_price,
                rental.rented_on,
                rental.return_by,
                book.id.label("book_id"),
                book.title,
                book.author,
                seller.qty.label("seller_qty"),
                seller.price.label("seller_price"),
                seller.rent_price.label("seller_rent_price"),
                seller_user.name.label("seller_name"),
                seller_user.email.label("seller_email")
            )
            .join(book, rental.book_id == book.id)
            .join(seller, (rental.seller_id == seller.id) & (rental.book_id == seller.book_id))
            .join(seller_user, seller.id == seller_user.id)  # Aliased join
            .filter(rental.user_id == user_data.id)
            .filter(rental.returned_on.is_(None))  # Only active rentals
            .order_by(rental.return_by.asc())
            .all()
        )

        rented_books_list = [
            {
                "rental_id": r.rental_id,
                "book_id": r.book_id,
                "title": r.title,
                "author": r.author,
                "rented_qty": r.rented_qty,
                "rented_price": r.rented_price,
                "rented_on": r.rented_on.strftime("%Y-%m-%d"),
                "return_by": r.return_by.strftime("%Y-%m-%d"),
                "seller_name": r.seller_name,
                "seller_email": r.seller_email,
                "seller_qty": r.seller_qty,
                "seller_price": r.seller_price,
                "seller_rent_price": r.seller_rent_price
            }
            for r in rented_books
        ]

        return jsonify(rented_books_list), 200

    except Exception as e:
        print("Error in /api/rented_books:", e)
        db.session.rollback()
        return jsonify({'error': str(e)}), 500



@app.route('/api/return_book/<int:rented_book_id>', methods=['POST'])
@jwt_required()
def return_book(rented_book_id):
    try:
        user_email = get_jwt_identity()
        user_data = user.query.filter_by(email=user_email).first()

        if not user_data:
            return jsonify({"error": "Invalid token or user not found"}), 401

        # Get the rental record
        rented_book = rental.query.filter_by(id=rented_book_id, user_id=user_data.id).first()

        if not rented_book:
            return jsonify({"error": "Rented book not found"}), 404

        # Check if already returned
        if rented_book.returned_on is not None:
            return jsonify({"error": "Book has already been returned."}), 400

        # Optional: Prevent return after due date
        # Use timezone-aware datetimes
        utc_now = datetime.datetime.now(pytz.UTC)

        if rented_book.return_by <= utc_now:
            return jsonify({"error": "The return date has already passed."}), 400

        # Mark the book as returned
        rented_book.returned_on = utc_now

        # Update the corresponding seller stock
        seller_entry = seller.query.filter_by(id=rented_book.seller_id, book_id=rented_book.book_id).first()

        if not seller_entry:
            return jsonify({"error": "Corresponding seller entry not found"}), 500  # Should never happen

        seller_entry.qty += rented_book.rented_qty

        db.session.commit()

        return jsonify({"message": "Book returned successfully"}), 200

    except Exception as e:
        print(e)
        db.session.rollback()
        return jsonify({'error': str(e)}), 500


# Run the app
if __name__ == '__main__':
    app.run(debug=True,host='0.0.0.0')


# import psycopg2
# from psycopg2 import sql

# # Set up the connection to the source and target databases
# source_db_config = {
#     'host': 'ems-db.cfuwga4qmhc5.ap-south-1.rds.amazonaws.com',
#     'dbname': 'ems-db',
#     'user': 'ems_user',
#     'password': 'KimbalEMS#123'
# }

# target_db_config = {
#     'host': 'ems-db.cfuwga4qmhc5.ap-south-1.rds.amazonaws.com',
#     'dbname': 'ems-uat-db',
#     'user': 'ems_user',
#     'password': 'KimbalEMS#123'
# }

# # Connect to the source database
# source_conn = psycopg2.connect(**source_db_config)
# source_cursor = source_conn.cursor()

# # Connect to the target database
# target_conn = psycopg2.connect(**target_db_config)
# target_cursor = target_conn.cursor()

# # Step 1: Get list of all tables from the source database
# source_cursor.execute("SELECT table_name FROM information_schema.tables WHERE table_schema='public';")
# tables = source_cursor.fetchall()

# # Step 2: Replicate each table (structure + data)
# for table in tables:
#     table_name = table[0]

#     # Skip the table 'state_time_mapping'
#     if table_name == 'test_sample':
#         print(f"Skipping table {table_name}...")
#         continue

#     print(f"Replicating table {table_name}...")

#     try:
#         # Check if the table already exists in the target database
#         target_cursor.execute(f"""
#             SELECT to_regclass('public.{table_name}');
#         """)
#         exists = target_cursor.fetchone()[0] is not None

#         if exists:
#             print(f"Table {table_name} already exists in target database. Skipping replication.")
#             continue  # Skip this table if it already exists in the target

#         # Step 2.1: Copy table schema (structure)
#         source_cursor.execute(f"""
#             SELECT column_name, data_type 
#             FROM information_schema.columns
#             WHERE table_schema = 'public' AND table_name = %s;
#         """, (table_name,))
#         columns = source_cursor.fetchall()

#         # Dynamically generate CREATE TABLE SQL, with proper quoting for reserved keywords
#         create_table_sql = f"CREATE TABLE IF NOT EXISTS {table_name} ("
#         create_table_sql += ", ".join([f'"{col[0]}" {col[1]}' if col[0].upper() in ['USER', 'TYPE', 'NAME'] else f"{col[0]} {col[1]}" for col in columns]) + ");"

#         # Create table in the target database
#         target_cursor.execute(create_table_sql)
#         print("table created successfully in target db")
#         # Step 2.2: Copy table data using batch inserts (to improve performance)
#         source_cursor.execute(f"SELECT * FROM {table_name};")
        
#         # Fetch the first batch of rows (5000 rows)
#         rows = source_cursor.fetchmany(5000)

#         # Create insert statement dynamically
#         placeholders = ', '.join(['%s'] * len(columns))
#         insert_sql = f"INSERT INTO {table_name} VALUES ({placeholders})"
        
#         # Loop through all batches of data
#         while rows:
#             # Insert data for the current batch
#             target_cursor.executemany(insert_sql, rows)
#             target_conn.commit()  # Commit after each batch insert
            
#             # Fetch the next batch of data
#             rows = source_cursor.fetchmany(5000)  # Fetch the next batch of 5000 rows

#         print(f"Table {table_name} replicated successfully.")

#     except Exception as e:
#         # Log the error and continue with the next table
#         print(f"Error replicating table {table_name}: {str(e)}")
#         print(f"Full error details: {e}")

# # Close the connections
# source_cursor.close()
# target_cursor.close()
# source_conn.close()
# target_conn.close()

# print("Database replication completed for all tables!")

# import psycopg2
# from psycopg2 import sql

# # Set up the connection to the source and target databases
# source_db_config = {
#     'host': 'ems-db.cfuwga4qmhc5.ap-south-1.rds.amazonaws.com',
#     'dbname': 'ems-db',
#     'user': 'ems_user',
#     'password': 'KimbalEMS#123'
# }

# target_db_config = {
#     'host': 'ems-db.cfuwga4qmhc5.ap-south-1.rds.amazonaws.com',
#     'dbname': 'ems-uat-db',
#     'user': 'ems_user',
#     'password': 'KimbalEMS#123'
# }

# # Connect to the source database
# source_conn = psycopg2.connect(**source_db_config)
# source_cursor = source_conn.cursor()

# # Connect to the target database
# target_conn = psycopg2.connect(**target_db_config)
# target_cursor = target_conn.cursor()

# # Step 1: Check if the table exists in the target database
# target_cursor.execute("""
#     SELECT to_regclass('public.test_sample');
# """)
# table_exists = target_cursor.fetchone()[0] is not None

# if not table_exists:
#     # If the table does not exist, create it
#     print("Creating the table 'test_sample' in the target database...")
    
#     create_table_sql = """
#     CREATE TABLE IF NOT EXISTS public.test_sample
#     (
#         id integer,
#         date date,
#         time_slot character varying(50),
#         predicted_consumption double precision,
#         predicted_consumption_kw double precision,
#         purchased_power_dam double precision,
#         predicted_discom_landed_cost double precision,
#         predicted_iex_landed_cost double precision,
#         bid_quantum double precision,
#         bid_price double precision,
#         decision_point decision_point_enum,
#         predicted_saving double precision,
#         predicted_saving_percentage double precision
#     );
#     """
    
#     target_cursor.execute(create_table_sql)
#     target_conn.commit()
#     print("Table 'test_sample' created successfully in the target database.")
# else:
#     print("Table 'test_sample' already exists in the target database. Skipping creation.")

# # Step 2: Fetch data from the source `test_sample` table
# source_cursor.execute("SELECT * FROM public.test_sample;")
# rows = source_cursor.fetchall()

# # Step 3: Insert data into the target `test_sample` table
# if rows:
#     # Dynamically generate the insert SQL statement
#     insert_sql = """
#         INSERT INTO public.test_sample 
#         (id, date, time_slot, predicted_consumption, predicted_consumption_kw, 
#         purchased_power_dam, predicted_discom_landed_cost, predicted_iex_landed_cost, 
#         bid_quantum, bid_price, decision_point, predicted_saving, predicted_saving_percentage)
#         VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s);
#     """
    
#     try:
#         target_cursor.executemany(insert_sql, rows)
#         target_conn.commit()
#         print(f"Data inserted into 'test_sample' table successfully.")
#     except Exception as e:
#         print(f"Error inserting data into 'test_sample' table: {e}")
#         target_conn.rollback()

# # Step 4: Close the connections
# source_cursor.close()
# target_cursor.close()
# source_conn.close()
# target_conn.close()

# print("Data replication completed successfully!")


# import psycopg2

# # Source and target DB configs
# source_db_config = {
#     'host': 'ems-db.cfuwga4qmhc5.ap-south-1.rds.amazonaws.com',
#     'dbname': 'ems-db',
#     'user': 'ems_user',
#     'password': 'KimbalEMS#123'
# }

# target_db_config = {
#     'host': 'ems-db.cfuwga4qmhc5.ap-south-1.rds.amazonaws.com',
#     'dbname': 'ems-uat-db',
#     'user': 'ems_user',
#     'password': 'KimbalEMS#123'
# }

# # Connect to source and target databases
# source_conn = psycopg2.connect(**source_db_config)
# source_cur = source_conn.cursor()

# target_conn = psycopg2.connect(**target_db_config)
# target_cur = target_conn.cursor()


# if not target_cur.fetchone()[0]:
#     print("Creating decision_point_predicted_data table in the target...")

#     create_table_sql = """
#     CREATE TABLE public.decision_point_predicted_data
#     (
#         id integer NOT NULL,
#         date date NOT NULL,
#         time_slot character varying(50) NOT NULL,
#         predicted_consumption double precision NOT NULL,
#         predicted_consumption_kw double precision NOT NULL,
#         predicted_iex_landed_cost double precision NOT NULL,
#         predicted_discom_landed_cost double precision NOT NULL,
#         bid_price double precision NOT NULL,
#         decision_point decision_point_enum NOT NULL,
#         predicted_saving double precision,
#         predicted_saving_percentage double precision,
#         bid_quantum double precision NOT NULL DEFAULT 0,
#         price_mean_absolute_error double precision NOT NULL DEFAULT 0,
#         conumption_mean_absolute_error double precision NOT NULL DEFAULT 0,
#         user_entered_bid_quantum double precision NOT NULL DEFAULT 0,
#         user_entered_bid_price double precision NOT NULL DEFAULT 0,
#         CONSTRAINT decision_point_predicted_data_pkey PRIMARY KEY (id),
#         CONSTRAINT unique_predicted_date_timeslot UNIQUE (date, time_slot)
#     );
#     """
#     target_cur.execute(create_table_sql)
#     target_conn.commit()
#     print(" → Table created successfully in the target.")

# else:
#     print("Table already exists in target. Skipping creation.")



# # Step 4: Fetch data from the source `decision_point_predicted_data` table
# source_cur.execute("""
#     SELECT id, date, time_slot, predicted_consumption, predicted_consumption_kw, predicted_iex_landed_cost, 
#            predicted_discom_landed_cost, bid_price, decision_point, predicted_saving, predicted_saving_percentage, 
#            bid_quantum, price_mean_absolute_error, conumption_mean_absolute_error, user_entered_bid_quantum, 
#            user_entered_bid_price FROM public.decision_point_predicted_data;
# """)
# rows = source_cur.fetchall()

# # Step 5: Insert data into the target `decision_point_predicted_data` table
# if rows:
#     insert_sql = """
#     INSERT INTO public.decision_point_predicted_data
#       (id, date, time_slot, predicted_consumption, predicted_consumption_kw, predicted_iex_landed_cost,
#        predicted_discom_landed_cost, bid_price, decision_point, predicted_saving, predicted_saving_percentage,
#        bid_quantum, price_mean_absolute_error, conumption_mean_absolute_error, user_entered_bid_quantum, user_entered_bid_price)
#     VALUES
#       (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
#     ON CONFLICT (date, time_slot) DO UPDATE SET
#       predicted_consumption          = EXCLUDED.predicted_consumption,
#       predicted_consumption_kw       = EXCLUDED.predicted_consumption_kw,
#       predicted_iex_landed_cost      = EXCLUDED.predicted_iex_landed_cost,
#       predicted_discom_landed_cost   = EXCLUDED.predicted_discom_landed_cost,
#       bid_price                      = EXCLUDED.bid_price,
#       decision_point                 = EXCLUDED.decision_point,
#       predicted_saving               = EXCLUDED.predicted_saving,
#       predicted_saving_percentage    = EXCLUDED.predicted_saving_percentage,
#       bid_quantum                    = EXCLUDED.bid_quantum,
#       price_mean_absolute_error      = EXCLUDED.price_mean_absolute_error,
#       conumption_mean_absolute_error = EXCLUDED.conumption_mean_absolute_error,
#       user_entered_bid_quantum       = EXCLUDED.user_entered_bid_quantum,
#       user_entered_bid_price         = EXCLUDED.user_entered_bid_price;
#     """
    
#     # Checking if the number of placeholders matches the number of columns
#     print(f"Expected number of placeholders: {len(rows[0])}, Insert SQL: {insert_sql}")

#     try:
#         target_cur.executemany(insert_sql, rows)
#         target_conn.commit()
#         print(f"Inserted/updated {len(rows)} rows into decision_point_predicted_data.")
#     except Exception as e:
#         print("Error inserting data:", e)
#         target_conn.rollback()
# else:
#     print("No rows found in source to copy.")

# # Step 6: Clean up
# source_cur.close()
# target_cur.close()
# source_conn.close()
# target_conn.close()
# print("Done.")


#HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH
# import psycopg2

# # ----  CONFIG  ---------------------------------------------------
# source_db = {
#     'host':     'ems-db.cfuwga4qmhc5.ap-south-1.rds.amazonaws.com',
#     'dbname':   'ems-db',
#     'user':     'ems_user',
#     'password': 'KimbalEMS#123'
# }
# target_db = {
#     'host':     'ems-db.cfuwga4qmhc5.ap-south-1.rds.amazonaws.com',
#     'dbname':   'ems-uat-db',
#     'user':     'ems_user',
#     'password': 'KimbalEMS#123'
# }
# BATCH_SIZE = 5000
# TABLE     = 'public.decision_point_predicted_data'
# # -----------------------------------------------------------------

# def main():
#     src = psycopg2.connect(**source_db)
#     tgt = psycopg2.connect(**target_db)
#     with src, src.cursor() as sc, tgt, tgt.cursor() as tc:

#         # 1) Ensure the enum type exists in target (skipped if already):
#         tc.execute("SELECT 1 FROM pg_type WHERE typname = 'decision_point_enum'")
#         if not tc.fetchone():
#             tc.execute("""
#             CREATE TYPE decision_point_enum AS ENUM ('DISCOM','IEX','IEX-DAM','IEX-GDAM');
#             """)

#         # 2) Ensure the target table exists:
#         tc.execute("SELECT to_regclass(%s)", (TABLE,))
#         if not tc.fetchone()[0]:
#             print("→ Creating table in target…")
#             tc.execute(f"""
#             CREATE TABLE {TABLE} (
#               id integer NOT NULL,
#               date date NOT NULL,
#               time_slot varchar(50) NOT NULL,
#               predicted_consumption   double precision NOT NULL,
#               predicted_consumption_kw double precision NOT NULL,
#               predicted_iex_landed_cost double precision NOT NULL,
#               predicted_discom_landed_cost double precision NOT NULL,
#               bid_price double precision NOT NULL,
#               decision_point decision_point_enum NOT NULL,
#               predicted_saving double precision,
#               predicted_saving_percentage double precision,
#               bid_quantum double precision NOT NULL DEFAULT 0,
#               price_mean_absolute_error double precision NOT NULL DEFAULT 0,
#               conumption_mean_absolute_error double precision NOT NULL DEFAULT 0,
#               user_entered_bid_quantum double precision NOT NULL DEFAULT 0,
#               user_entered_bid_price    double precision NOT NULL DEFAULT 0,
#               CONSTRAINT decision_point_predicted_data_pkey PRIMARY KEY (id),
#               CONSTRAINT unique_predicted_date_timeslot UNIQUE (date, time_slot)
#             );
#             """)
#             tgt.commit()
#             print("✔ table created.")
#         else:
#             print("→ Table already exists; skipping CREATE.")

#         # 3) Discover source columns dynamically:
#         sc.execute(f"SELECT * FROM {TABLE} LIMIT 0")
#         cols = [d[0] for d in sc.description]
#         col_list   = ", ".join(cols)
#         placeholders = ", ".join(["%s"] * len(cols))
#         # Build ON CONFLICT DO UPDATE clause for all non-PK columns
#         conflict_updates = ", ".join(
#             f"{c}=EXCLUDED.{c}" for c in cols
#             if c not in ('date', 'time_slot')  # unique key
#         )

#         upsert_sql = f"""
#         INSERT INTO {TABLE} ({col_list})
#         VALUES ({placeholders})
#         ON CONFLICT (date, time_slot) DO UPDATE
#           SET {conflict_updates}
#         """

#         # 4) Fetch from source in batches, upsert to target
#         sc.execute(f"SELECT * FROM {TABLE}")
#         total = 0
#         while True:
#             batch = sc.fetchmany(BATCH_SIZE)
#             if not batch:
#                 break
#             tc.executemany(upsert_sql, batch)
#             tgt.commit()
#             total += len(batch)
#             print(f"  → upserted {len(batch)} rows (total {total})")

#         print("✅ All done!")

# if __name__ == "__main__":
#     main()

# import psycopg2

# # --- CONFIG -----------------------------------------------------------------
# SOURCE_DB = {
#     'host':     'ems-db.cfuwga4qmhc5.ap-south-1.rds.amazonaws.com',
#     'dbname':   'ems-db',
#     'user':     'ems_user',
#     'password': 'KimbalEMS#123'
# }
# TARGET_DB = {
#     'host':     'ems-db.cfuwga4qmhc5.ap-south-1.rds.amazonaws.com',
#     'dbname':   'ems-uat-db',
#     'user':     'ems_user',
#     'password': 'KimbalEMS#123'
# }
# TABLE_NAME = 'public.decision_point_predicted_data_rtm'
# BATCH_SIZE = 5000
# # ---------------------------------------------------------------------------

# def main():
#     src_conn = psycopg2.connect(**SOURCE_DB)
#     tgt_conn = psycopg2.connect(**TARGET_DB)

#     with src_conn, src_conn.cursor() as sc, tgt_conn, tgt_conn.cursor() as tc:
#         # 1) Ensure enum exists in target
#         tc.execute("SELECT 1 FROM pg_type WHERE typname = 'decision_point_enum'")
#         if not tc.fetchone():
#             tc.execute("""
#               CREATE TYPE decision_point_enum AS ENUM (
#                 'DISCOM','IEX','IEX-DAM','IEX-GDAM'
#               );
#             """)
#             tgt_conn.commit()
#             print("✔ Created decision_point_enum in target")

#         # 2) Create RTM table if missing
#         tc.execute("SELECT to_regclass(%s)", (TABLE_NAME,))
#         if not tc.fetchone()[0]:
#             print(f"→ Creating {TABLE_NAME} …")
#             tc.execute(f"""
#             CREATE TABLE {TABLE_NAME}
#             (
#                 id integer NOT NULL,
#                 date date,
#                 time_slot character varying(50),
#                 predicted_consumption double precision,
#                 predicted_consumption_kw double precision,
#                 purchased_power_dam double precision,
#                 predicted_discom_landed_cost double precision,
#                 predicted_iex_landed_cost double precision,
#                 bid_quantum double precision,
#                 bid_price double precision,
#                 decision_point decision_point_enum,
#                 predicted_saving double precision,
#                 predicted_saving_percentage double precision,
#                 user_entered_bid_quantum double precision NOT NULL DEFAULT 0,
#                 user_entered_bid_price double precision NOT NULL DEFAULT 0,
#                 purchased_power_gdam double precision NOT NULL DEFAULT 0,
#                 CONSTRAINT decision_point_predicted_data_rtm_pkey PRIMARY KEY (id),
#                 CONSTRAINT unique_predicted_date_timeslot_rtm1 UNIQUE (date, time_slot)
#             );
#             """)
#             tgt_conn.commit()
#             print("✔ Table created in target")
#         else:
#             print("→ Table already exists; skipping CREATE")

#         # 3) Discover source columns
#         sc.execute(f"SELECT * FROM {TABLE_NAME} LIMIT 0")
#         cols = [d[0] for d in sc.description]
#         col_list     = ", ".join(cols)
#         placeholders = ", ".join(["%s"] * len(cols))

#         # Build the ON CONFLICT DO UPDATE clause for all non-unique-key columns
#         # (we keep date+time_slot as the uniqueness constraint)
#         update_cols = [c for c in cols if c not in ('date', 'time_slot')]
#         updates = ", ".join(f"{c}=EXCLUDED.{c}" for c in update_cols)

#         upsert_sql = f"""
#         INSERT INTO {TABLE_NAME} ({col_list})
#         VALUES ({placeholders})
#         ON CONFLICT (date, time_slot) DO UPDATE
#           SET {updates};
#         """

#         # 4) Fetch & upsert in batches
#         print("→ Copying data in batches…")
#         sc.execute(f"SELECT * FROM {TABLE_NAME}")
#         total = 0
#         while True:
#             batch = sc.fetchmany(BATCH_SIZE)
#             if not batch:
#                 break
#             tc.executemany(upsert_sql, batch)
#             tgt_conn.commit()
#             total += len(batch)
#             print(f"   • Upserted {len(batch)} rows (total {total})")

#         print(f"✅ Finished upserting {total} rows into {TABLE_NAME}")

# if __name__ == "__main__":
#     main()
