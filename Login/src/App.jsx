import React from "react";
import { BrowserRouter as Router, Route, Routes } from "react-router-dom";
import LoginPage from "./loginPage";  // Import the LoginPage component
import SecretPage from "./secrets"; // Import the SecretPage component

function App() {
  return (
    <Router>
      <Routes>
        <Route path="/" element={<LoginPage />} />
        <Route path="/secrets" element={<SecretPage />} />
      </Routes>
    </Router>
  );
}

export default App;
