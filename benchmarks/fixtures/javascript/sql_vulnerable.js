function findUser(userId) {
  const query = "SELECT * FROM users WHERE id = " + userId;
  db.query(query);
}
