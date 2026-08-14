function readDocument(req) {
  const safeName = path.basename(req.query.filename);
  fs.readFile(safeName, () => {});
}

