def build_user_query(user_id):
    query = "SELECT * FROM users WHERE id = " + user_id
    return query


def load_user(user_id):
    return build_user_query(user_id)
