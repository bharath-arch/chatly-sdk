export class PostgreSQLUserStore {
  constructor(pool) {
    this.pool = pool;
  }

  async create(user) {
    await this.pool.query(
      `INSERT INTO users (id, username, public_key, private_key) 
       VALUES ($1, $2, $3, $4)`,
      [user.id, user.username, user.publicKey, user.privateKey]
    );
    return user;
  }

  async findById(id) {
    const result = await this.pool.query(
      `SELECT id, username, public_key as "publicKey", private_key as "privateKey" 
       FROM users WHERE id = $1`,
      [id]
    );
    return result.rows[0];
  }

  async save(user) {
    await this.pool.query(
      `UPDATE users 
       SET username = $1, public_key = $2 
       WHERE id = $3`,
      [user.username, user.publicKey, user.id]
    );
  }

  async list() {
    const result = await this.pool.query(
      `SELECT id, username, public_key as "publicKey", private_key as "privateKey" 
       FROM users`
    );
    return result.rows;
  }
}
