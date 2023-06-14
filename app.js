// Import required modules
const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const sqlite3 = require("sqlite3").verbose();

// Create an instance of Express app
const app = express();

// Middleware for JSON parsing
app.use(express.json());

// Create a new SQLite database instance
const db = new sqlite3.Database("twitterClone.db");

// API 1: User Registration
app.post("/register", (req, res) => {
  const { username, password, name, gender } = req.body;

  // Check if the username already exists
  db.get(
    "SELECT user_id FROM user WHERE username = ?",
    [username],
    (err, row) => {
      if (err) {
        console.error(err);
        res.status(500).send("Internal Server Error");
      } else if (row) {
        res.status(400).send("User already exists");
      } else if (password.length < 6) {
        res.status(400).send("Password is too short");
      } else {
        // Hash the password
        bcrypt.hash(password, 10, (err, hashedPassword) => {
          if (err) {
            console.error(err);
            res.status(500).send("Internal Server Error");
          } else {
            // Insert user details into the database
            db.run(
              "INSERT INTO user (name, username, password, gender) VALUES (?, ?, ?, ?)",
              [name, username, hashedPassword, gender],
              (err) => {
                if (err) {
                  console.error(err);
                  res.status(500).send("Internal Server Error");
                } else {
                  res.status(200).send("User created successfully");
                }
              }
            );
          }
        });
      }
    }
  );
});

// API 2: User Login
app.post("/login", (req, res) => {
  const { username, password } = req.body;

  // Retrieve user details from the database
  db.get(
    "SELECT user_id, password FROM user WHERE username = ?",
    [username],
    (err, row) => {
      if (err) {
        console.error(err);
        res.status(500).send("Internal Server Error");
      } else if (!row) {
        res.status(400).send("Invalid user");
      } else {
        // Compare passwords
        bcrypt.compare(password, row.password, (err, result) => {
          if (err) {
            console.error(err);
            res.status(500).send("Internal Server Error");
          } else if (!result) {
            res.status(400).send("Invalid password");
          } else {
            // Generate and return a JWT token
            const jwtToken = jwt.sign({ user_id: row.user_id }, "secret_key");
            res.json({ jwtToken });
          }
        });
      }
    }
  );
});

// Middleware for JWT token authentication
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (token === undefined) {
    res.status(401).send("Invalid JWT Token");
  } else {
    jwt.verify(token, "secret_key", (err, user) => {
      if (err) {
        console.error(err);
        res.status(401).send("Invalid JWT Token");
      } else {
        req.user = user;
        next();
      }
    });
  }
}

// API 3: User Tweets Feed
// API 3: Get Latest Tweets from People User Follows
app.get("/user/tweets/feed", authenticateToken, (req, res) => {
  const userId = req.user.user_id;

  // Retrieve the latest 4 tweets from people whom the user follows
  db.all(
    `SELECT tweet.tweet, tweet.date_time, user.username
    FROM tweet
    JOIN follower ON follower.following_user_id = tweet.user_id
    JOIN user ON tweet.user_id = user.user_id
    WHERE follower.follower_user_id = ?
    ORDER BY tweet.date_time DESC
    LIMIT 4`,
    [userId],
    (err, rows) => {
      if (err) {
        console.error(err);
        res.status(500).send("Internal Server Error");
      } else {
        const tweets = rows.map((row) => ({
          username: row.username,
          tweet: row.tweet,
          dateTime: row.date_time,
        }));
        res.json(tweets);
      }
    }
  );
});

// API 4: User Following
app.get("/user/following", authenticateToken, (req, res) => {
  const userId = req.user.user_id;

  // Retrieve the list of names of people whom the user follows
  db.all(
    `SELECT user.name
    FROM user
    JOIN follower ON user.user_id = follower.following_user_id
    WHERE follower.follower_user_id = ?`,
    [userId],
    (err, rows) => {
      if (err) {
        console.error(err);
        res.status(500).send("Internal Server Error");
      } else {
        res.json(rows);
      }
    }
  );
});

// API 5: User Followers
app.get("/user/followers", authenticateToken, (req, res) => {
  const userId = req.user.user_id;

  // Retrieve the list of names of people who follow the user
  db.all(
    `SELECT user.name
    FROM user
    JOIN follower ON user.user_id = follower.follower_user_id
    WHERE follower.following_user_id = ?`,
    [userId],
    (err, rows) => {
      if (err) {
        console.error(err);
        res.status(500).send("Internal Server Error");
      } else {
        res.json(rows);
      }
    }
  );
});

// API 6: Get Tweet Details
app.get("/tweets/:tweetId", authenticateToken, (req, res) => {
  const userId = req.user.user_id;
  const tweetId = req.params.tweetId;

  // Check if the user is authorized to access the tweet
  db.get(
    `SELECT tweet.tweet, tweet.user_id, tweet.date_time,
    (SELECT COUNT(*) FROM like WHERE tweet_id = tweet.tweet_id) AS likes,
    (SELECT COUNT(*) FROM reply WHERE tweet_id = tweet.tweet_id) AS replies
    FROM tweet
    JOIN follower ON follower.following_user_id = tweet.user_id
    WHERE tweet.tweet_id = ? AND follower.follower_user_id = ?`,
    [tweetId, userId],
    (err, row) => {
      if (err) {
        console.error(err);
        res.status(500).send("Internal Server Error");
      } else if (!row) {
        res.status(401).send("Invalid Request");
      } else {
        const { tweet, user_id, date_time, likes, replies } = row;
        res.json({ tweet, likes, replies, dateTime: date_time });
      }
    }
  );
});
// API 7: Get Likes for a Tweet
app.get("/tweets/:tweetId/likes", authenticateToken, (req, res) => {
  const userId = req.user.user_id;
  const tweetId = req.params.tweetId;

  // Check if the user is authorized to access the tweet
  db.get(
    `SELECT tweet.user_id
    FROM tweet
    JOIN follower ON follower.following_user_id = tweet.user_id
    WHERE tweet.tweet_id = ? AND follower.follower_user_id = ?`,
    [tweetId, userId],
    (err, row) => {
      if (err) {
        console.error(err);
        res.status(500).send("Internal Server Error");
      } else if (!row) {
        res.status(401).send("Invalid Request");
      } else {
        // Retrieve the list of usernames who liked the tweet
        db.all(
          `SELECT user.username
          FROM user
          JOIN "like" ON user.user_id = "like".user_id
          WHERE "like".tweet_id = ?`,
          [tweetId],
          (err, rows) => {
            if (err) {
              console.error(err);
              res.status(500).send("Internal Server Error");
            } else {
              const likes = rows.map((row) => row.username);
              res.json({ likes });
            }
          }
        );
      }
    }
  );
});

// API 8: Get Replies for a Tweet
app.get("/tweets/:tweetId/replies", authenticateToken, (req, res) => {
  const userId = req.user.user_id;
  const tweetId = req.params.tweetId;

  // Check if the user is authorized to access the tweet
  db.get(
    `SELECT tweet.user_id
    FROM tweet
    JOIN follower ON follower.following_user_id = tweet.user_id
    WHERE tweet.tweet_id = ? AND follower.follower_user_id = ?`,
    [tweetId, userId],
    (err, row) => {
      if (err) {
        console.error(err);
        res.status(500).send("Internal Server Error");
      } else if (!row) {
        res.status(401).send("Invalid Request");
      } else {
        // Retrieve the list of replies for the tweet
        db.all(
          `SELECT user.name, reply.reply
          FROM reply
          JOIN user ON user.user_id = reply.user_id
          WHERE reply.tweet_id = ?`,
          [tweetId],
          (err, rows) => {
            if (err) {
              console.error(err);
              res.status(500).send("Internal Server Error");
            } else {
              const replies = rows.map((row) => ({
                name: row.name,
                reply: row.reply,
              }));
              res.json({ replies });
            }
          }
        );
      }
    }
  );
});

// API 9: Get User's Tweets
app.get("/user/tweets", authenticateToken, (req, res) => {
  const userId = req.user.user_id;

  // Retrieve all tweets of the logged-in user
  db.all(
    `SELECT tweet.tweet, tweet.date_time
    FROM tweet
    WHERE tweet.user_id = ?`,
    [userId],
    (err, rows) => {
      if (err) {
        console.error(err);
        res.status(500).send("Internal Server Error");
      } else {
        const tweets = rows.map((row) => ({
          tweet: row.tweet,
          dateTime: row.date_time,
        }));
        res.json(tweets);
      }
    }
  );
});

// API 10: Create a Tweet
app.post("/user/tweets", authenticateToken, (req, res) => {
  const userId = req.user.user_id;
  const { tweet } = req.body;

  // Insert the tweet into the tweet table
  const dateTime = new Date().toISOString();
  db.run(
    `INSERT INTO tweet (tweet, user_id, date_time)
    VALUES (?, ?, ?)`,
    [tweet, userId, dateTime],
    (err) => {
      if (err) {
        console.error(err);
        res.status(500).send("Internal Server Error");
      } else {
        res.send("Created a Tweet");
      }
    }
  );
});

// API 11: Delete a Tweet
app.delete("/tweets/:tweetId", authenticateToken, (req, res) => {
  const userId = req.user.user_id;
  const tweetId = req.params.tweetId;

  // Check if the user is authorized to delete the tweet
  db.get(
    `SELECT user_id
    FROM tweet
    WHERE tweet_id = ?`,
    [tweetId],
    (err, row) => {
      if (err) {
        console.error(err);
        res.status(500).send("Internal Server Error");
      } else if (!row) {
        res.status(401).send("Invalid Request");
      } else if (row.user_id !== userId) {
        res.status(401).send("Invalid Request");
      } else {
        // Delete the tweet from the tweet table
        db.run(
          `DELETE FROM tweet
          WHERE tweet_id = ?`,
          [tweetId],
          (err) => {
            if (err) {
              console.error(err);
              res.status(500).send("Internal Server Error");
            } else {
              res.send("Tweet Removed");
            }
          }
        );
      }
    }
  );
});

module.exports = app;
