function decodeSession(req) {
  return deserialize(req.body.session);
}

