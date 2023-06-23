PRAGMA foreign_keys = ON;

-- users
INSERT INTO users(username, fullname, email, filename, password, created)
VALUES ('awdeorio', 'Andrew DeOrio', 'awdeorio@umich.edu', 'e1a7c5c32973862ee15173b0259e3efdb6a391af.jpg',
'sha512$a45ffdcc71884853a2cba9e6bc55e812$c739cef1aec45c6e345c8463136dc1ae2fe19963106cf748baf87c7102937aa96928aa1db7fe1d8da6bd343428ff3167f4500c8a61095fb771957b4367868fb8',
datetime('now'));

INSERT INTO users(username, fullname, email, filename, password, created)
VALUES ('jflinn', 'Jason Flinn', 'jflinn@umich.edu', '505083b8b56c97429a728b68f31b0b2a089e5113.jpg',
'sha512$a45ffdcc71884853a2cba9e6bc55e812$c739cef1aec45c6e345c8463136dc1ae2fe19963106cf748baf87c7102937aa96928aa1db7fe1d8da6bd343428ff3167f4500c8a61095fb771957b4367868fb8',
datetime('now'));

INSERT INTO users(username, fullname, email, filename, password, created)
VALUES ('michjc', 'Michael Cafarella', 'michjc@umich.edu', '5ecde7677b83304132cb2871516ea50032ff7a4f.jpg',
'sha512$a45ffdcc71884853a2cba9e6bc55e812$c739cef1aec45c6e345c8463136dc1ae2fe19963106cf748baf87c7102937aa96928aa1db7fe1d8da6bd343428ff3167f4500c8a61095fb771957b4367868fb8',
datetime('now'));

INSERT INTO users(username, fullname, email, filename, password, created)
VALUES ('jag', 'H.V. Jagadish', 'jag@umich.edu', '73ab33bd357c3fd42292487b825880958c595655.jpg',
'sha512$a45ffdcc71884853a2cba9e6bc55e812$c739cef1aec45c6e345c8463136dc1ae2fe19963106cf748baf87c7102937aa96928aa1db7fe1d8da6bd343428ff3167f4500c8a61095fb771957b4367868fb8',
datetime('now'));

-- posts
INSERT INTO posts(filename, owner, created)
VALUES ('122a7d27ca1d7420a1072f695d9290fad4501a41.jpg', 'awdeorio', datetime('now'));

INSERT INTO posts(filename, owner, created)
VALUES ('ad7790405c539894d25ab8dcf0b79eed3341e109.jpg', 'jflinn', datetime('now'));

INSERT INTO posts(filename, owner, created)
VALUES ('9887e06812ef434d291e4936417d125cd594b38a.jpg', 'awdeorio', datetime('now'));

INSERT INTO posts(filename, owner, created)
VALUES ('2ec7cf8ae158b3b1f40065abfb33e81143707842.jpg', 'jag', datetime('now'));

-- following
INSERT INTO following(username1, username2, created)
VALUES ('awdeorio', 'jflinn', datetime('now'));

INSERT INTO following(username1, username2, created)
VALUES ('awdeorio', 'michjc', datetime('now'));

INSERT INTO following(username1, username2, created)
VALUES ('jflinn', 'awdeorio', datetime('now'));

INSERT INTO following(username1, username2, created)
VALUES ('jflinn', 'michjc', datetime('now'));

INSERT INTO following(username1, username2, created)
VALUES ('michjc', 'awdeorio', datetime('now'));

INSERT INTO following(username1, username2, created)
VALUES ('michjc', 'jag', datetime('now'));

-- comments
INSERT INTO comments(owner, postid, text, created)
VALUES('awdeorio', 3, '#chickensofinstagram', datetime('now'));

INSERT INTO comments(owner, postid, text, created)
VALUES('jflinn', 3, 'I <3 chickens', datetime('now'));

INSERT INTO comments(owner, postid, text, created)
VALUES('michjc', 3, 'Cute overload!', datetime('now'));

INSERT INTO comments(owner, postid, text, created)
VALUES('awdeorio', 2, 'Sick #crossword', datetime('now'));

INSERT INTO comments(owner, postid, text, created)
VALUES('jflinn', 1, 'Walking the plank #chickensofinstagram', datetime('now'));

INSERT INTO comments(owner, postid, text, created)
VALUES('awdeorio', 1, 'This was after trying to teach them to do a #crossword', datetime('now'));

INSERT INTO comments(owner, postid, text, created)
VALUES('jag', 4, "Saw this on the diag yesterday!", datetime('now'));

-- likes
INSERT INTO likes(owner, postid, created)
VALUES('awdeorio', 1, datetime('now'));

INSERT INTO likes(owner, postid, created)
VALUES('michjc', 1, datetime('now'));

INSERT INTO likes(owner, postid, created)
VALUES('jflinn', 1, datetime('now'));

INSERT INTO likes(owner, postid, created)
VALUES('awdeorio', 2, datetime('now'));

INSERT INTO likes(owner, postid, created)
VALUES('michjc', 2, datetime('now'));

INSERT INTO likes(owner, postid, created)
VALUES('awdeorio', 3, datetime('now'));
