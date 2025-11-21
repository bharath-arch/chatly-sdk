export class PostgreSQLGroupStore {
  constructor(pool) {
    this.pool = pool;
  }

  async create(group) {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      
      // Insert group
      await client.query(
        'INSERT INTO groups (id, name, shared_secret) VALUES ($1, $2, $3)',
        [group.id, group.name, group.sharedSecret]
      );
      
      // Insert members
      for (const userId of group.members) {
        await client.query(
          'INSERT INTO group_members (group_id, user_id) VALUES ($1, $2)',
          [group.id, userId]
        );
      }
      
      await client.query('COMMIT');
      return group;
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  async findById(id) {
    const groupResult = await this.pool.query(
      'SELECT id, name, shared_secret as "sharedSecret" FROM groups WHERE id = $1',
      [id]
    );
    
    if (groupResult.rows.length === 0) return undefined;
    
    const membersResult = await this.pool.query(
      'SELECT user_id FROM group_members WHERE group_id = $1',
      [id]
    );
    
    return {
      ...groupResult.rows[0],
      members: membersResult.rows.map(row => row.user_id)
    };
  }

  async list() {
    const groupsResult = await this.pool.query(
      'SELECT id, name, shared_secret as "sharedSecret" FROM groups'
    );
    
    const groups = [];
    for (const group of groupsResult.rows) {
      const membersResult = await this.pool.query(
        'SELECT user_id FROM group_members WHERE group_id = $1',
        [group.id]
      );
      groups.push({
        ...group,
        members: membersResult.rows.map(row => row.user_id)
      });
    }
    
    return groups;
  }
}
