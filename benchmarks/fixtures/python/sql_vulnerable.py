def find_user(user_id):
    cursor.execute("SELECT * FROM users WHERE id = " + user_id)  # noqa: F821
