/** User class for message.ly */
const db = require("../db");
const ExpressError = require("../expressError");
const { DB_URI, BCRYPT_WORK_FACTOR } = require("../config");
const bcrypt = require("bcrypt");




/** User of the site. */

class User {
  /** register new user -- returns
   *    {username, password, first_name, last_name, phone}
   */
  static async register(username, password, first_name, last_name, phone) {
    let hashedPassword = await bcrypt(password, BCRYPT_WORK_FACTOR);
    const result = await db.query(
      `
    INSERT INTO users (username, password, first_name,last_name,phone)
    VALUES ($1, $2, $3, $4, $5) RETURNING username, password,
    first_name, last_name, phone`,
      [username, hashedPassword, first_name, last_name, phone]
    );
    return result.rows[0];
  }

  /** Authenticate: is this username/password valid? Returns boolean. */

  static async authenticate(username, password) {
    const result = await db.query(
      `SELECT 
    password FROM users WHERE username = $1`,
      [username]
    );
    let user = result.rows[0];
    return user && (await bcrypt.compare(password, user.password));
  }

  /** Update last_login_at for user */

  static async updateLoginTimestamp(username) {
    const result = await db.query(
      `UPDATE users SET
    last_login_at = CURRENT_TIMESTAMP
    WHERE username = $1 RETURNING username`,
      [username]
    );
    if (!result.rows[0]) {
      throw new ExpressError(`User: ${username} not found`, 404);
    }
  }

  /** All: basic info on all users:
   * [{username, first_name, last_name, phone}, ...] */

  static async all() {
    const results = await db.query(`
    SELECT username, first_name, last_name, phone
    FROM users ORDER BY username`);
    const users = results.rows.map(
      (u) => u.username,
      u.first_name,
      u.last_name,
      u.phone
    );
    return users;
  }

  /** Get: get user by username
   *
   * returns {username,
   *          first_name,
   *          last_name,
   *          phone,
   *          join_at,
   *          last_login_at } */

  static async get(username) {
    const result = await db.query(
      `
    SELECT * from users WHERE 
    username = $1`,
      [username]
    );
    if (!result.rows[0]) {
      throw new ExpressError(`User ${username} not found`, 404);
    }
    return result.rows[0];
  }

  /** Return messages from this user.
   *
   * [{id, to_user, body, sent_at, read_at}]
   *
   * where to_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesFrom(username) {
    const results = await db.query(
      `SELECT
    m.id, m.to_username, m.body, m.sent_at, m.read_at,
    u.first_name, u.last_name, u.phone
    FROM messages AS m JOIN users AS u 
    ON m.to_username = u.username
    WHERE from_username = $1 `,
      [username]
    );
    return results.rows.map(
      (m) => (
        {
          message: {
            id: m.id,
            to: m.to_username,
            body: m.body,
            sent_at: m.sent_at,
            read_at: m.read_at,
          },
        },
        {
          to_user: {
            username: m.to_username,
            first_name: m.first_name,
            last_name: m.last_name,
            phone: m.phone,
          },
        }
      )
    );
  }

  /** Return messages to this user.
   *
   * [{id, from_user, body, sent_at, read_at}]
   *
   * where from_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesTo(username) {
    const results = await db.query(
      `
    SELECT m.id, m.from_username, m.body, m.sent_at, m.read_at,
    u.username, u.first_name, u.last_name, u.phone
    FROM messages AS m JOIN users AS u
    ON m.from_username = u.username
    WHERE to_username = $1`,
      [username]
    );
    return results.rows.map(
      (m) => (
        {
          message: {
            id: m.id,
            from: m.from_username,
            body: m.body,
            sent_at: m.sent_at,
            read_at: m.read_at,
          },
        },
        {
          from_user: {
            username: m.from_username,
            first_name: m.first_name,
            last_name: m.last_name,
            phone: m.phone,
          },
        }
      )
    );
  }
}


module.exports = User;