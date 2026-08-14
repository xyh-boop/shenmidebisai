def read_document(filename):
    safe_name = os.path.basename(filename)  # noqa: F821
    return open(safe_name).read()
