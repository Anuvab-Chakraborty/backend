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



with app.app_context():
    db.create_all()
    

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

        rented_subquery = (
            db.session.query(
                rental.seller_id.label("seller_id"),
                rental.book_id.label("book_id"),
                func.coalesce(func.sum(rental.rented_qty), 0).label("rented_qty")
            )
            .filter(rental.returned_on == None)
            .group_by(rental.seller_id, rental.book_id)
        ).subquery()

        books_with_sellers = (
            db.session.query(
                book.id.label("book_id"),
                book.title,
                book.author,
                seller.id.label("seller_id"),
                user.name.label("seller_name"),
                user.email.label("seller_email"),
                seller.price,
                seller.rent_price,
                (seller.qty - func.coalesce(rented_subquery.c.rented_qty, 0)).label("available_qty")
            )
            .join(seller, book.id == seller.book_id)
            .join(user, seller.id == user.id)
            .outerjoin(
                rented_subquery,
                (rented_subquery.c.seller_id == seller.id) &
                (rented_subquery.c.book_id == book.id)
            )
            .filter((seller.qty - func.coalesce(rented_subquery.c.rented_qty, 0)) > 0)
            .order_by(book.title)
            .offset(offset)
            .limit(limit)
            .all()
        )

        # Check if there are more books available
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
                "buy_price": entry.price,
                "rent_price": entry.rent_price,
                "available_qty": entry.available_qty,
                "seller_email":entry.seller_email,
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
        # Get book details
        book_details = db.session.query(book).filter_by(id=book_id).first()
        if not book_details:
            return jsonify({"error": "Book not found"}), 404

        # Get seller-wise availability with LEFT OUTER JOIN to include all sellers even if no rentals
        availability_data = db.session.query(
            seller.id.label("seller_id"),
            user.name.label("seller_name"),  # Joining user table to get the seller's name
            seller.price.label("buy_price"),
            seller.rent_price,
            seller.qty.label("total_qty"),
            func.coalesce(func.sum(rental.rented_qty), 0).label("rented_qty"),
            (seller.qty - func.coalesce(func.sum(rental.rented_qty), 0)).label("available_qty"),
            func.min(rental.return_by).label("next_available_date")
        ).join(user, user.id == seller.id) \
        .outerjoin(rental, (rental.seller_id == seller.id) & (rental.book_id == book_id)) \
         .filter(seller.book_id == book_id) \
         .group_by(seller.id, user.name, seller.price, seller.rent_price, seller.qty) \
         .all()

        result = []
        for s in availability_data:
            result.append({
                "seller_id": s.seller_id,
                "seller_name": s.seller_name,
                "buy_price": s.buy_price,
                "rent_price": s.rent_price,
                "total_qty": s.total_qty,
                "rented_qty": s.rented_qty,
                "available_qty": s.available_qty,
                "next_available_date": s.next_available_date.isoformat() if s.next_available_date else None
            })

        return jsonify(result), 200

    except Exception as ex:
        print(ex)
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
            user_id=get_jwt_identity(),
            seller_id=seller_id,
            book_id=book_id,
            bought_qty=qty,
            bought_price=s.sell_price * qty,  # Assuming the price is per book
            bought_on=datetime.utcnow()
        )
        db.session.add(p)
        db.session.commit()

        return jsonify({'message': f'Successfully bought {qty} book(s)'}), 200

    except SQLAlchemyError as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500
    except Exception as e:
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
        if return_by <= datetime.utcnow():
            return jsonify({'error': 'Return date must be in the future'}), 400

        s = seller.query.filter_by(id=seller_id, book_id=book_id).first()
        if not s:
            return jsonify({'error': 'Seller not found'}), 404

        if s.qty < qty:
            return jsonify({'error': 'Not enough quantity available'}), 400

        # Decrease available quantity
        s.qty -= qty

        # Create rental record
        r = rental(
            user_id=get_jwt_identity(),
            seller_id=seller_id,
            book_id=book_id,
            rented_qty=qty,
            rented_price=s.rent_price * qty,
            rented_on=datetime.utcnow(),
            return_by=return_by
        )
        db.session.add(r)
        db.session.commit()

        return jsonify({'message': f'Rented {qty} book(s) until {return_by.date()}'}), 200

    except SQLAlchemyError as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# Flask route to fetch the purchased books
@app.route('/api/purchased_books', methods=['GET'])
@jwt_required()
def get_purchased_books():
    try:
        user_email = get_jwt_identity()
        user_data = user.query.filter_by(email=user_email).first()

        if not user_data:
            return jsonify({"error": "Invalid token or user not found"}), 401

        purchased_books = purchase.query.filter_by(user_id=user_data.id).all()

        # Convert the purchased books to a list of dictionaries
        purchased_books_list = [
            {
                'id': book.id,
                'title': book.book.title,
                'purchased_on': book.purchased_on
            }
            for book in purchased_books
        ]

        return jsonify(purchased_books_list), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Flask route to fetch the rented books
@app.route('/api/rented_books', methods=['GET'])
@jwt_required()
def get_rented_books():
    try:
        user_email = get_jwt_identity()
        user_data = user.query.filter_by(email=user_email).first()

        if not user_data:
            return jsonify({"error": "Invalid token or user not found"}), 401

        rented_books = rental.query.filter_by(user_id=user_data.id).all()

        # Convert the rented books to a list of dictionaries
        rented_books_list = [
            {
                'id': book.id,
                'title': book.book.title,
                'return_by': book.return_by
            }
            for book in rented_books
        ]

        return jsonify(rented_books_list), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Flask route to handle returning a rented book
@app.route('/api/return_book/<int:rented_book_id>', methods=['POST'])
@jwt_required()
def return_book(rented_book_id):
    try:
        user_email = get_jwt_identity()
        user_data = user.query.filter_by(email=user_email).first()

        if not user_data:
            return jsonify({"error": "Invalid token or user not found"}), 401

        rented_book = rental.query.filter_by(id=rented_book_id, user_id=user_data.id).first()

        if not rented_book:
            return jsonify({"error": "Rented book not found"}), 404

        # Check if the book is overdue
        if rented_book.return_by <= datetime.utcnow():
            return jsonify({"error": "The return date has already passed."}), 400

        # Proceed with returning the book (update availability, etc.)
        rented_book.returned_on = datetime.utcnow()
        rented_book.status = 'returned'  # Assuming you track the status of rented books

        # Update book stock if necessary
        book = book.query.filter_by(id=rented_book.book_id).first()
        book.qty += rented_book.rented_qty  # Assuming rented_qty is stored

        db.session.commit()

        return jsonify({"message": "Book returned successfully"}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

# Run the app
if __name__ == '__main__':
    app.run(debug=True,host='0.0.0.0')