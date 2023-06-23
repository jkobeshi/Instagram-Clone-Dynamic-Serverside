"""
Insta485 index (main) view.

URLs include:
/
"""
import uuid
import hashlib
import pathlib
import os
import arrow
import flask
from flask import send_from_directory
from flask import abort
import insta485


def cookie_protocol():
    """Verify login."""
    connection = insta485.model.get_db()
    username = flask.request.cookies.get("username")
    password = flask.request.cookies.get("password")
    cur = connection.execute(
        "SELECT count(*) AS cnt FROM users "
        "WHERE username == ? AND password == ?",
        (
            username,
            password,
        ),
    )
    if cur.fetchall()[0]["cnt"] == 0:
        return False
    return True


@insta485.app.route("/")
def show_index():
    """Display / route."""
    # Connect to database
    connection = insta485.model.get_db()
    if cookie_protocol() is False:
        return flask.make_response(flask.redirect(
            flask.url_for("show_accounts_login")))

    # Query database
    logname = flask.request.cookies.get("username")

    cur = connection.execute(
        "SELECT posts.*, users.filename AS pfp "
        "FROM posts, users, following "
        "WHERE posts.owner == users.username AND ((following.username1 == ? "
        "AND posts.owner == following.username2) OR (posts.owner == ?))"
        "GROUP BY posts.postid "
        "ORDER BY posts.postid DESC",
        (logname, logname),
    )
    posts = cur.fetchall()

    for i in posts:
        cur = connection.execute(
            "SELECT COUNT(*) AS like "
            "FROM likes "
            "WHERE likes.postid == ?",
            (i["postid"],),
        )
        count = cur.fetchall()
        i["like"] = count[0]["like"]

    for i in posts:
        cur = connection.execute(
            "SELECT owner, text "
            "FROM comments "
            "WHERE comments.postid == ?",
            (i["postid"],),
        )
        i["comments"] = cur.fetchall()

    for i in posts:
        cur = connection.execute(
            "SELECT owner "
            "FROM likes "
            "WHERE likes.postid == ? AND likes.owner == ?",
            (
                i["postid"],
                logname,
            ),
        )
        liked = cur.fetchall()
        i["liked_post"] = len(liked)

    for i in posts:
        arrow.get(i["created"])
        utc = arrow.utcnow()
        i["timestamp"] = utc.humanize()

    # Add database info to context
    context = {"logname": logname, "posts": posts}
    return flask.render_template("index.html", **context)


@insta485.app.route("/users/<path:user>/")
def show_users(user):
    """Display /users/ route."""
    # Connect to database
    connection = insta485.model.get_db()
    if cookie_protocol() is False:
        return flask.make_response(flask.redirect(
            flask.url_for("show_accounts_login")))
    # Query database
    logname = flask.request.cookies.get("username")

    # abort if user not found in db
    cur = connection.execute(
        "SELECT username "
        "FROM users "
        "WHERE username == ? ",
        (user,)
    )
    if len(cur.fetchall()) == 0:
        abort(404)

    cur = connection.execute(
        "SELECT * "
        "FROM following "
        "WHERE username1 == ? AND username2 == ?",
        (
            logname,
            user,
        ),
    )
    follows = cur.fetchall()
    logname_follows_username = True
    if len(follows) == 0:
        logname_follows_username = False

    cur = connection.execute(
        "SELECT * "
        "FROM following "
        "WHERE username2 == ?",
        (user,)
    )
    followers = len(cur.fetchall())

    cur = connection.execute(
        "SELECT * "
        "FROM following "
        "WHERE username1 == ?",
        (user,)
    )
    following = len(cur.fetchall())

    cur = connection.execute(
        "SELECT fullname "
        "FROM users "
        "WHERE username == ?",
        (user,)
    )
    fullname = cur.fetchall()[0]["fullname"]

    cur = connection.execute(
        "SELECT * "
        "FROM posts "
        "WHERE owner == ?",
        (user,)
    )
    posts = cur.fetchall()
    # Add database info to context
    context = {
        "logname": logname,
        "username": user,
        "logname_follows_username": logname_follows_username,
        "followers": followers,
        "following": following,
        "fullname": fullname,
        "posts": posts,
        "total_posts": len(posts),
    }
    return flask.render_template("user.html", **context)


@insta485.app.route("/users/<path:user>/followers/")
def show_followers(user):
    """Display /users/<user>/followers route."""
    # Connect to database
    connection = insta485.model.get_db()
    if cookie_protocol() is False:
        return flask.make_response(flask.redirect(
            flask.url_for("show_accounts_login")))
    # Query database
    logname = flask.request.cookies.get("username")

    cur = connection.execute(
        "SELECT users.filename AS filename, users.username AS username "
        "FROM following, users "
        "WHERE following.username2 == ? AND "
        "following.username1 == users.username",
        (user,),
    )
    followers = cur.fetchall()

    for i in followers:
        cur = connection.execute(
            "SELECT * FROM following "
            "WHERE username1 == ? AND username2 == ?",
            (logname, i["username"]),
        )
        i["logname_follows_username"] = True
        if len(cur.fetchall()) == 0:
            i["logname_follows_username"] = False

    # Add database info to context
    context = {"logname": logname, "followers": followers}
    return flask.render_template("followers.html", **context)


@insta485.app.route("/users/<path:user>/following/")
def show_following(user):
    """Display /users/<user>/following route."""
    # Connect to database
    connection = insta485.model.get_db()
    if cookie_protocol() is False:
        return flask.make_response(flask.redirect(
            flask.url_for("show_accounts_login")))
    # Query database
    logname = flask.request.cookies.get("username")

    cur = connection.execute(
        "SELECT users.filename AS filename, users.username AS username "
        "FROM following, users "
        "WHERE following.username1 == ? AND "
        "following.username2 == users.username",
        (user,),
    )
    following = cur.fetchall()

    for i in following:
        cur = connection.execute(
            "SELECT * FROM following WHERE username1 == ? AND username2 == ?",
            (logname, i["username"]),
        )
        i["logname_follows_username"] = True
        if len(cur.fetchall()) == 0:
            i["logname_follows_username"] = False

    # Add database info to context
    context = {"logname": logname, "following": following}
    return flask.render_template("following.html", **context)


@insta485.app.route("/posts/<path:post_id>/")
def show_posts(post_id):
    """Display /posts/<path> route."""
    # Connect to database
    connection = insta485.model.get_db()
    if cookie_protocol() is False:
        return flask.make_response(flask.redirect(
            flask.url_for("show_accounts_login")))
    # Query database
    logname = flask.request.cookies.get("username")
    cur = connection.execute(
        "SELECT * "
        "FROM posts "
        "WHERE postid == ?",
        (post_id,)
    )
    post = cur.fetchall()[0]

    arrow.get(post["created"])
    utc = arrow.utcnow()
    post["timestamp"] = utc.humanize()

    cur = connection.execute(
        "SELECT filename "
        "FROM users "
        "WHERE username == ?",
        (post["owner"],)
    )
    owner_img_url = cur.fetchall()[0]["filename"]

    cur = connection.execute(
        "SELECT count(*) AS cnt "
        "FROM likes "
        "WHERE postid == ?",
        (post_id,)
    )
    likes = cur.fetchall()[0]["cnt"]

    cur = connection.execute(
        "SELECT * "
        "FROM comments "
        "WHERE postid == ?", (post_id,)
    )
    comment = cur.fetchall()

    cur = connection.execute(
        "SELECT count(*) AS count "
        "FROM likes "
        "WHERE owner == ? AND postid == ?",
        (
            logname,
            post_id,
        ),
    )
    liked_post = cur.fetchall()[0]["count"]

    # Add database info to context
    context = {
        "logname": logname,
        "post": post,
        "owner_img_url": owner_img_url,
        "likes": likes,
        "comments": comment,
        "liked_post": liked_post,
    }
    return flask.render_template("post.html", **context)


@insta485.app.route("/explore/")
def show_explore():
    """Display /explore/ route."""
    # Connect to database
    connection = insta485.model.get_db()
    if cookie_protocol() is False:
        return flask.make_response(flask.redirect(
            flask.url_for("show_accounts_login")))
    # Query database
    logname = flask.request.cookies.get("username")

    cur = connection.execute(
        "SELECT users.username, users.filename "
        "FROM users "
        "WHERE users.username != ?",
        (logname,),
    )
    users_without_logname = cur.fetchall()

    not_following = []
    for i in users_without_logname:
        cur = connection.execute(
            "SELECT users.username, users.filename "
            "FROM following, users "
            "WHERE following.username1 == ? AND following.username2 == ?",
            (logname, i["username"]),
        )
        following = cur.fetchall()
        if len(following) == 0:
            not_following.append(i)

    # Add database info to context
    context = {"logname": logname, "not_following": not_following}
    return flask.render_template("explore.html", **context)


def login_helper(connection, resp):
    """Login helper."""
    username = flask.request.form["username"]
    password = flask.request.form["password"]

    if len(username) == 0 or len(password) == 0:
        abort(400)

    cur = connection.execute(
        "SELECT password "
        "FROM users "
        "WHERE username == ?",
        (username,)
    )
    exists = cur.fetchall()
    # verifies that username exists
    if len(exists) == 0:
        # Does not Exists
        abort(403)

    str_after_sha = exists[0]["password"].partition("$")[2]
    salt = str_after_sha.partition("$")[0]

    # password hashing
    algorithm = "sha512"
    # salt = uuid.uuid4().hex
    hash_obj = hashlib.new(algorithm)
    password_salted = salt + password
    hash_obj.update(password_salted.encode("utf-8"))
    password_hash = hash_obj.hexdigest()

    password_db_string = "$".join([algorithm, salt, password_hash])

    if password_db_string != exists[0]["password"]:
        # Does not exist
        abort(403)

    resp.set_cookie("username", username)
    resp.set_cookie("password", password_db_string)


def create_helper(connection, resp):
    """Create helper."""
    username = flask.request.form["username"]
    password = flask.request.form["password"]
    fullname = flask.request.form["fullname"]
    email = flask.request.form["email"]
    fileobj = flask.request.files["file"]
    file = fileobj.filename

    if (
        len(username) == 0
        or len(password) == 0
        or len(fullname) == 0
        or len(email) == 0
        or len(file) == 0
    ):
        abort(400)

    cur = connection.execute(
        "SELECT * FROM users WHERE username == ?",
        (username,)
    )
    if len(cur.fetchall()) > 0:
        abort(409)

    algorithm = "sha512"
    salt = uuid.uuid4().hex
    hash_obj = hashlib.new(algorithm)
    password_salted = salt + password
    hash_obj.update(password_salted.encode("utf-8"))
    password_db_string = "$".join([algorithm, salt, hash_obj.hexdigest()])

    cur = connection.execute(
        "INSERT INTO users(username, fullname, email, "
        "filename, password, created) "
        "VALUES (?, ?, ?, ?, ?, datetime('now'))",
        (
            username,
            fullname,
            email,
            file,
            password_db_string,
        ),
    )
    resp.set_cookie("username", username)
    resp.set_cookie("password", password_db_string)


def delete_helper(connection, resp):
    """Delete helper."""
    if cookie_protocol() is False:
        abort(403)
    else:
        username = flask.request.cookies.get("username")
        connection.execute(
            "DELETE FROM users WHERE username == ?", (username,)
        )
    resp.set_cookie("username", "", expires=0)
    resp.set_cookie("password", "", expires=0)


def edit_account_helper(connection):
    """Edit account helper."""
    if cookie_protocol() is False:
        abort(403)
    fullname = flask.request.form["fullname"]
    email = flask.request.form["email"]
    if len(fullname) == 0 or len(email) == 0:
        abort(400)

    fileobj = flask.request.files["file"]
    filename = fileobj.filename

    username = flask.request.cookies.get("username")

    connection.execute(
        "UPDATE users "
        "SET fullname = ? "
        "WHERE username == ?",
        (fullname, username),
    )
    connection.execute(
        "UPDATE users "
        "SET email = ? "
        "WHERE username == ?", (email, username)
    )

    if len(filename) != 0:
        # there is a picture to update
        stem = uuid.uuid4().hex
        suffix = pathlib.Path(filename).suffix.lower()
        uuid_basename = f"{stem}{suffix}"
        # Save to disk
        path = insta485.app.config["UPLOAD_FOLDER"] / uuid_basename
        fileobj.save(path)
        connection.execute(
            "UPDATE users "
            "SET filename = ? "
            "WHERE username == ?",
            (uuid_basename, username),
        )


def update_password_helper(connection, resp):
    """Update password helper."""
    if cookie_protocol() is False:
        abort(403)
    username = flask.request.cookies.get("username")
    password = flask.request.form["password"]
    new_password1 = flask.request.form["new_password1"]
    new_password2 = flask.request.form["new_password2"]

    if len(password) == 0 or len(
            new_password1) == 0 or len(new_password2) == 0:
        abort(400)

    cur = connection.execute(
        "SELECT * FROM users WHERE username = ?",
        (username,)
    )
    user_info = cur.fetchall()

    str_after_sha = user_info[0]["password"].partition("$")[2]
    salt = str_after_sha.partition("$")[0]

    algorithm = "sha512"
    salt = uuid.uuid4().hex
    hash_obj = hashlib.new(algorithm)
    password_salted = salt + password
    hash_obj.update(password_salted.encode("utf-8"))
    password_hash = hash_obj.hexdigest()
    password_db_string = "$".join([algorithm, salt, password_hash])

    if password_db_string == user_info[0]["password"]:
        abort(403)

    if new_password1 != new_password2:
        abort(401)

    algorithm = "sha512"
    salt = uuid.uuid4().hex
    hash_obj = hashlib.new(algorithm)
    password_salted = salt + new_password1
    hash_obj.update(password_salted.encode("utf-8"))
    password_hash = hash_obj.hexdigest()
    password_db_string = "$".join([algorithm, salt, password_hash])

    cur = connection.execute(
        "UPDATE users "
        "SET password = ? "
        "WHERE username == ?",
        (
            password_db_string,
            username,
        ),
    )
    resp.set_cookie("password", password_db_string)


@insta485.app.route("/accounts/", methods=["POST"])
def show_accounts():
    """Post account."""
    # Connect to database
    connection = insta485.model.get_db()
    operation = flask.request.form["operation"]
    target = flask.request.args.get("target")
    if len(str(target)) == 0 or target is None:
        target = "/"
    resp = flask.make_response(flask.redirect(target))

    if operation == "login":
        login_helper(connection, resp)
    elif operation == "create":
        create_helper(connection, resp)
    elif operation == "delete":
        delete_helper(connection, resp)
    elif operation == "edit_account":
        edit_account_helper(connection)
    elif operation == "update_password":
        update_password_helper(connection, resp)

    return resp


@insta485.app.route("/accounts/login/")
def show_accounts_login():
    """Display /accounts/login."""
    if cookie_protocol() is True:
        return flask.make_response(flask.redirect(
            flask.url_for("show_index")))
    return flask.render_template("login.html")


@insta485.app.route("/accounts/create/")
def show_accounts_create():
    """Display /accounts/create."""
    if cookie_protocol() is True:
        return flask.make_response(flask.redirect(
            flask.url_for("show_accounts_edit")))
    return flask.render_template("create.html")


@insta485.app.route("/accounts/delete/")
def show_accounts_delete():
    """Display /accounts/delete."""
    context = {"username": flask.request.cookies.get("username")}
    return flask.render_template("delete.html", **context)


@insta485.app.route("/accounts/edit/")
def show_accounts_edit():
    """Display /accounts/edit."""
    if cookie_protocol() is False:
        abort(403)
    # Connect to database
    connection = insta485.model.get_db()

    # Query database
    logname = flask.request.cookies.get("username")

    cur = connection.execute(
        "SELECT * "
        "FROM users "
        "WHERE username == ?",
        (logname,)
    )
    users = cur.fetchall()[0]

    # Add database info to context
    context = {"users": users, "logname": logname}
    return flask.render_template("edit.html", **context)


@insta485.app.route("/accounts/password/")
def show_accounts_password():
    """Display /accounts/password."""
    if cookie_protocol() is False:
        return flask.make_response(flask.redirect(
            flask.url_for("show_accounts_login")))

    context = {"logname": flask.request.cookies.get("username")}
    return flask.render_template("password.html", **context)


@insta485.app.route("/accounts/logout/", methods=["POST"])
def show_accounts_logout():
    """Handle logout."""
    if cookie_protocol() is False:
        return flask.make_response(flask.redirect(
            flask.url_for("show_accounts_login")))
    resp = flask.make_response(flask.redirect(
        flask.url_for("show_accounts_login")))
    resp.set_cookie("username", "", expires=0)
    resp.set_cookie("password", "", expires=0)
    return resp


@insta485.app.route("/likes/", methods=["POST"])
def show_likes():
    """Handle /likes/ operation."""
    if cookie_protocol() is False:
        return flask.make_response(flask.redirect(
            flask.url_for("show_accounts_login")))

    # Connect to database
    connection = insta485.model.get_db()

    operation = flask.request.form["operation"]
    target = flask.request.args.get("target")

    if len(str(target)) == 0 or target is None:
        target = "/"

    resp = flask.make_response(flask.redirect(target))
    username = flask.request.cookies.get("username")
    postid = flask.request.form["postid"]

    if operation == "like":
        cur = connection.execute(
            "SELECT * FROM likes WHERE owner == ? AND postid == ?",
            (
                username,
                postid,
            ),
        )
        if len(cur.fetchall()) != 0:
            abort(409)

        cur = connection.execute(
            "INSERT INTO likes(owner, postid, created) "
            "VALUES (?, ?, datetime('now'))",
            (
                username,
                postid,
            ),
        )

    elif operation == "unlike":
        cur = connection.execute(
            "SELECT * FROM likes WHERE owner == ? AND postid == ?",
            (
                username,
                postid,
            ),
        )
        if len(cur.fetchall()) == 0:
            abort(409)

        cur = connection.execute(
            "DELETE FROM likes WHERE owner == ? AND postid == ?",
            (
                username,
                postid,
            ),
        )

    return resp


@insta485.app.route("/comments/", methods=["POST"])
def show_comment():
    """Handle /comments/ operation."""
    if cookie_protocol() is False:
        return flask.make_response(flask.redirect(
            flask.url_for("show_accounts_login")))

    # Connect to database
    connection = insta485.model.get_db()

    operation = flask.request.form["operation"]
    target = flask.request.args.get("target")

    if len(str(target)) == 0 or target is None:
        target = "/"

    resp = flask.make_response(flask.redirect(target))
    username = flask.request.cookies.get("username")

    if operation == "create":
        postid = flask.request.form["postid"]
        text = flask.request.form["text"]
        if len(text) == 0:
            abort(400)
        cur = connection.execute(
            "INSERT INTO comments(owner, postid, text, created) "
            "VALUES (?, ?, ?, datetime('now'))",
            (
                username,
                postid,
                text,
            ),
        )

    elif operation == "delete":
        commentid = flask.request.form["commentid"]

        cur = connection.execute(
            "SELECT owner FROM comments WHERE commentid == ?", (commentid,)
        )
        if cur.fetchall()[0]["owner"] != username:
            abort(403)

        cur = connection.execute(
            "DELETE FROM comments WHERE owner == ? AND commentid == ?",
            (
                username,
                commentid,
            ),
        )

    return resp


@insta485.app.route("/posts/", methods=["POST"])
def posts_ops():
    """Handle POST for posts."""
    if cookie_protocol() is False:
        return flask.make_response(flask.redirect(
            flask.url_for("show_accounts_login")))

    # Connect to database
    connection = insta485.model.get_db()

    operation = flask.request.form["operation"]
    target = flask.request.args.get("target")
    username = flask.request.cookies.get("username")

    if len(str(target)) == 0 or target is None:
        target = "/users/" + username + "/"

    resp = flask.make_response(flask.redirect(target))

    if operation == "create":
        fileobj = flask.request.files["file"]
        filename = fileobj.filename

        if len(filename) == 0:
            abort(400)

        stem = uuid.uuid4().hex
        suffix = pathlib.Path(filename).suffix.lower()
        uuid_basename = f"{stem}{suffix}"

        # Save to disk
        path = insta485.app.config["UPLOAD_FOLDER"] / uuid_basename
        fileobj.save(path)

        cur = connection.execute(
            "INSERT INTO posts(filename, owner, created) "
            "VALUES (?, ?, datetime('now'))",
            (uuid_basename, username),
        )

    elif operation == "delete":
        postid = flask.request.form["postid"]
        cur = connection.execute(
            "SELECT owner, filename FROM posts WHERE postid == ?", (postid,)
        )
        post = cur.fetchall()
        if post[0]["owner"] != username:
            abort(403)

        cur = connection.execute(
            "DELETE FROM posts WHERE postid == ? AND owner == ?",
            (
                postid,
                username,
            ),
        )

        os.remove(
            os.path.join(
                insta485.app.config["UPLOAD_FOLDER"], post[0]["filename"])
        )
    return resp


@insta485.app.route("/following/", methods=["POST"])
def following_ops():
    """Handle POST for following."""
    if cookie_protocol() is False:
        return flask.make_response(flask.redirect(
            flask.url_for("show_accounts_login")))

    # Connect to database
    connection = insta485.model.get_db()

    operation = flask.request.form["operation"]
    target = flask.request.args.get("target")
    username = flask.request.cookies.get("username")

    if len(str(target)) == 0 or target is None:
        target = "/"

    resp = flask.make_response(flask.redirect(target))

    to_be_followed = flask.request.form["username"]

    if operation == "follow":
        cur = connection.execute(
            "SELECT count(*) AS cnt FROM following "
            "WHERE username1 == ? AND username2 == ?",
            (
                username,
                to_be_followed,
            ),
        )
        if cur.fetchall()[0]["cnt"] != 0:
            abort(409)

        cur = connection.execute(
            "INSERT INTO following(username1, username2, created) "
            "VALUES (?, ?, datetime('now'))",
            (
                username,
                to_be_followed,
            ),
        )
    elif operation == "unfollow":
        cur = connection.execute(
            "SELECT count(*) AS cnt FROM following "
            "WHERE username1 == ? AND username2 == ?",
            (
                username,
                to_be_followed,
            ),
        )
        if cur.fetchall()[0]["cnt"] == 0:
            abort(409)

        cur = connection.execute(
            "DELETE FROM following WHERE username1 == ? AND username2 == ?",
            (
                username,
                to_be_followed,
            ),
        )
    return resp


@insta485.app.route("/uploads/<path:filename>")
def download_file(filename):
    """Download file."""
    # Connect to database
    connection = insta485.model.get_db()

    # static file permissions
    if cookie_protocol() is False:
        abort(403)

    cur = connection.execute(
        "SELECT count(*) AS cnt FROM users, posts "
        "WHERE users.filename == ? OR posts.filename == ?",
        (
            filename,
            filename,
        ),
    )
    if cur.fetchall()[0]["cnt"] == 0:
        abort(404)

    return send_from_directory(
        insta485.app.config["UPLOAD_FOLDER"], filename, as_attachment=True
    )
