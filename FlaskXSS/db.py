import sqlite3
from sqlite3.dbapi2 import Connection

# Create SQLite3 Database instance
def connect_db() -> Connection:
    # Connect to SQLite3 Database file
    db = sqlite3.connect('database.db')
    # If comments table does not exist, create one
    db.cursor().execute('CREATE TABLE IF NOT EXISTS comments '
                        '(id INTEGER PRIMARY KEY, '
                        'comment TEXT)')
    db.commit()
    return db


# Append comment to comments table of datatable
def add_comment(comment) -> None:
    db = connect_db()
    # Execute SQL statement to insert comment argument into comments table
    db.cursor().execute('INSERT INTO comments (comment) '
                        'VALUES (?)', (comment,))
    db.commit()


# Retrieve comments from database based on a search_query string
# Retrieves all comments if no search_query string is supplied
def get_comments(search_query=None):
    db = connect_db()
    # Create list of results to append comments to
    results = []
    # Query to retrieve all comments from comments table, in descending order of ID
    get_all_query = 'SELECT comment FROM comments ORDER BY ID DESC'
    # Loop through all comments, if search query argument value is in comment, append to results
    for (comment,) in db.cursor().execute(get_all_query).fetchall():
        if search_query is None or search_query in comment:
            results.append(comment)

    return results

"""
FLASKXSS IS BASED ON: https://github.com/bgres/xss-demo
"""
