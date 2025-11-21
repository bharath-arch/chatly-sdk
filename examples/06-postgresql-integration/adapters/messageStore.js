export class PostgreSQLMessageStore {
  constructor(pool) {
    this.pool = pool;
  }

  async create(message) {
    await this.pool.query(
      `INSERT INTO messages (id, sender_id, receiver_id, group_id, ciphertext, iv, timestamp, status) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [
        message.id,
        message.senderId,
        message.receiverId || null,
        message.groupId || null,
        message.ciphertext,
        message.iv,
        message.timestamp,
        message.status || 'pending'
      ]
    );
    return message;
  }

  async listByUser(userId) {
    const result = await this.pool.query(
      `SELECT id, sender_id as "senderId", receiver_id as "receiverId", 
              group_id as "groupId", ciphertext, iv, timestamp, status
       FROM messages 
       WHERE receiver_id = $1 OR sender_id = $1 
       ORDER BY timestamp ASC`,
      [userId]
    );
    return result.rows;
  }

  async listByGroup(groupId) {
    const result = await this.pool.query(
      `SELECT id, sender_id as "senderId", receiver_id as "receiverId", 
              group_id as "groupId", ciphertext, iv, timestamp, status
       FROM messages 
       WHERE group_id = $1 
       ORDER BY timestamp ASC`,
      [groupId]
    );
    return result.rows;
  }
}
