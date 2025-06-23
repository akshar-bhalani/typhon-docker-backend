# Typhon Django Project Setup Guide

This guide will help you set up and run the Typhon Django project on Windows, Ubuntu, and macOS using Python 3.10.

## Prerequisites

- Python 3.10
- PostgreSQL
- pgAdmin 4

## Setting Up Virtual Environment

### Windows
```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
.\venv\Scripts\activate
```

### Ubuntu/Linux
```bash
# Create virtual environment
python3.10 -m venv venv

# Activate virtual environment
source venv/bin/activate
```

### macOS
```bash
# Create virtual environment
python3.10 -m venv venv

# Activate virtual environment
source venv/bin/activate
```

## Installing Dependencies

Once your virtual environment is activated, install the project dependencies:

```bash
pip install -r requirements.txt
```

## Database Setup

1. Open pgAdmin 4
2. Right-click on "Databases" in the left sidebar
3. Select "Create" → "Database"
4. Enter the following details:
   - Database name: typhon
   - Owner: postgres (or your custom user)
5. Click "Save"



## Database Migrations

Run the following commands to set up your database schema:

```bash
# Make migrations
python manage.py makemigrations

# Apply migrations
python manage.py migrate
```

## Running the Development Server

Start the Django development server:

```bash
python manage.py runserver
```

The server will start at `http://127.0.0.1:8000/`



