import { BrowserRouter as Router, Routes, Route, Link } from 'react-router-dom';
import { useState } from 'react';
import logo from './assets/prodigy_infotech_logo.jpg';
import './App.css';
import Register from './Register';
import axios from 'axios';

function App() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setSuccess('');

    try {
      const response = await axios.post('http://localhost:5000/api/login', {
        email,
        password,
      });

      setSuccess('Login successful!');
      console.log('Response:', response.data);
    } catch (err) {
      setError(err.response?.data?.error || 'An error occurred');
      console.error('Error:', err);
    }
  };

  return (
    <Router>
      <Routes>
        <Route
          path="/"
          element={
            <div className="flex min-h-full flex-1 flex-col justify-center px-6 py-12 lg:px-8">
              <div className="sm:mx-auto sm:w-full sm:max-w-sm">
                <img alt="Logo" src={logo} className="mx-auto h-30 w-auto" />
                <h2 className="mt-10 text-center text-2xl/9 font-bold tracking-tight text-gray-900">
                  Sign in to your account
                </h2>
              </div>

              <div className="mt-10 sm:mx-auto sm:w-full sm:max-w-sm">
                <form onSubmit={handleSubmit} method="POST" className="space-y-6">
                  <div>
                    <label htmlFor="email" className="block text-sm/6 font-medium text-gray-900">
                      Email address
                    </label>
                    <div className="mt-2">
                      <input
                        id="email"
                        name="email"
                        type="email"
                        required
                        autoComplete="email"
                        value={email}
                        onChange={(e) => setEmail(e.target.value)}
                        className="block w-full rounded-md bg-white px-3 py-1.5 text-base text-gray-900 outline-1 -outline-offset-1 outline-gray-300 placeholder:text-gray-400 focus:outline-2 focus:-outline-offset-2 focus:outline-indigo-600 sm:text-sm/6"
                      />
                    </div>
                  </div>

                  <div>
                    <div className="flex items-center justify-between">
                      <label htmlFor="password" className="block text-sm/6 font-medium text-gray-900">
                        Password
                      </label>
                      <div className="text-sm">
                        <a href="#" className="font-semibold text-indigo-600 hover:text-indigo-500">
                          Forgot password?
                        </a>
                      </div>
                    </div>
                    <div className="mt-2">
                      <input
                        id="password"
                        name="password"
                        type="password"
                        required
                        autoComplete="current-password"
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                        className="block w-full rounded-md bg-white px-3 py-1.5 text-base text-gray-900 outline-1 -outline-offset-1 outline-gray-300 placeholder:text-gray-400 focus:outline-2 focus:-outline-offset-2 focus:outline-indigo-600 sm:text-sm/6"
                      />
                    </div>
                  </div>

                  <div>
                    <button
                      type="submit"
                      className="flex w-full justify-center rounded-md bg-indigo-600 px-3 py-1.5 text-sm/6 font-semibold text-white shadow-xs hover:bg-indigo-500 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-indigo-600"
                    >
                      Sign in
                    </button>
                  </div>
                </form>
                {error && <p className="mt-4 text-center text-sm text-red-500">{error}</p>}
                {success && <p className="mt-4 text-center text-sm text-green-500">{success}</p>}

                <p className="mt-10 text-center text-sm/6 text-gray-500">
                  Don't have an account?{' '}
                  <Link to="/register" className="font-semibold text-indigo-600 hover:text-indigo-500">
                    Register now
                  </Link>
                </p>
              </div>
            </div>
          }
        />
        <Route path="/register" element={<Register />} />
      </Routes>
    </Router>
  );
}

export default App;