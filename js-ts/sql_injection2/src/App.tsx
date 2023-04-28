import * as React from 'react';

interface User {
  id: number;
  username: string;
  email: string;
}

interface AppState {
  username: string;
  users: User[];
  error: string | null;
}

class Application extends React.Component<{}, AppState> {
  constructor(props: {}) {
    super(props);
    this.state = {
      username: '',
      users: [],
      error: null,
    };
  }

  componentDidMount() {
    // fetch users data and store in state
    const users = [
      { id: 1, username: 'alice', email: 'alice@example.com' },
      { id: 2, username: 'bob', email: 'bob@example.com' },
      { id: 3, username: 'charlie', email: 'charlie@example.com' },
    ];
    this.setState({ users });
  }

  render() {
    return (
      <div>
        <label htmlFor="username-input">Enter a username:</label>
        <input
          id="username-input"
          type="text"
          value={this.state.username}
          onChange={this.handleUsernameChange}
        />
        <button onClick={this.handleSubmit}>Submit</button>
        <div>
          {this.state.error && <p>{this.state.error}</p>}
          {this.state.users.length > 0 && (
            <ul>
              {this.state.users.map((user) => (
                <li key={user.id}>
                  {user.username} ({user.email})
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
    );
  }

  handleUsernameChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    this.setState({ username: event.target.value });
  };

  handleSubmit = () => {
    const { username } = this.state;
    const query = `SELECT * FROM users WHERE username='${username}'`;
    alert(`Executing query: ${query}`);
  };
}

export default Application;
