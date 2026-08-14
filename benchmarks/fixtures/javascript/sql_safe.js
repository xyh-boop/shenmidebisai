function findUser(userId) {
  db.query("SELECT * FROM users WHERE id = ?", [userId]);
}

