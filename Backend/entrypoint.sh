#!/bin/sh

echo "Initializing database..."
python init_db.py

echo "Starting Flask application..."
python app.py