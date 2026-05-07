function createInitialData() {
  return {
    users: {
      alice: { password: "123456", balance: 10000 },
      bob: { password: "123456", balance: 10000 },
      mallory: { password: "123456", balance: 10000 }
    },
    events: [],
    comments: [
      {
        id: 1,
        author: "system",
        createdAt: new Date().toLocaleString(),
        content:
          "Welcome to the demo comment board. This section is intentionally unsafe and renders HTML directly."
      }
    ]
  };
}

const state = createInitialData();

function resetDB() {
  const fresh = createInitialData();

  state.users = fresh.users;
  state.events = fresh.events;
  state.comments = fresh.comments;
}

module.exports = {
  state,
  resetDB
};