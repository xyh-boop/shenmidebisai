function readDocument(req) {
  fs.readFile(req.query.filename, () => {});
}

