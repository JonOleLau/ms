import * as React from 'react';

interface AppState {
  userInput: string;
}

class Application extends React.Component<{}, AppState> {
  constructor(props: {}) {
    super(props);
    this.state = {
      userInput: '',
    };
  }

  render() {
    return (
      <div>
        <h2>Vulnerability 1: Unsanitized User Input</h2>
        <label htmlFor="userInput">Enter a message:</label>
        <input
          id="userInput"
          type="text"
          value={this.state.userInput}
          onChange={this.handleUserInputChange}
        />
        <button onClick={this.displayMessage}>Display Message</button>
        <div id="message"></div>

        <h2>Vulnerability 2: Injected Script in URL</h2>
        <div id="querystring"></div>

        <h2>Vulnerability 3: Unsafe InnerHTML Assignment</h2>
        <div id="image"></div>
        <button onClick={this.displayImage}>Display Image</button>
      </div>
    );
  }

  handleUserInputChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    this.setState({ userInput: event.target.value });
  };

  displayMessage = () => {
    const { userInput } = this.state;
    const messageDiv = document.getElementById('message');
    if (messageDiv !== null) {
      messageDiv.innerHTML = userInput;
      console.log(`User Input: ${userInput}`);
    }
  };
  

  displayImage = () => {
    const imgSrcElement = document.getElementById('imageInput') as HTMLInputElement;
    const imageDiv = document.getElementById('image');
    if (imgSrcElement !== null && imageDiv !== null) {
      const imgSrc = imgSrcElement.value;
      imageDiv.innerHTML = `<img src="${imgSrc}">`;
      console.log(`Image Source: ${imgSrc}`);
    }
  };
  

  componentDidMount() {
    // fetch query string and store in state
    const queryString = window.location.search;
    const querystringDiv = document.getElementById('querystring');
    if (querystringDiv !== null) {
      querystringDiv.innerHTML = queryString;
      console.log(`Query String: ${queryString}`);
    }
  }
  
}

export default Application;
