import axios from "axios";

// Adjust baseURL if backend runs elsewhere
const api = axios.create({
  baseURL: "http://127.0.0.1:5000",
  timeout: 60000
});

export default api;
