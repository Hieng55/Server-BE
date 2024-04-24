const fs = require("fs");
const bodyParser = require("body-parser");
const jsonServer = require("json-server");
const jwt = require("jsonwebtoken");
const queryString = require("query-string");

const server = jsonServer.create();
const router = jsonServer.router("./database.json");
const userdb = JSON.parse(fs.readFileSync("./users.json", "UTF-8"));
server.use(bodyParser.urlencoded({ extended: true }));
server.use(bodyParser.json());
server.use(jsonServer.defaults());

const SECRET_KEY = "123456789";

// list api not have check auth
const API_NOT_AUTH = ["/products", "/categories", "/brands", "/carts", "/orders", "/userCarts", "/reviews", "/comments"];

const expiresIn = "1h";

// Create a token from a payload
function createToken(payload) {
  return jwt.sign(payload, SECRET_KEY, { expiresIn });
}

// Verify the token
function verifyToken(token) {
  return jwt.verify(token, SECRET_KEY, (err, decode) => (decode !== undefined ? decode : err));
}

// Check if the user exists in database
function isAuthenticated({ email, password }) {
  return userdb.users.findIndex((user) => user.email === email && user.password === password) !== -1;
}

// Register New User
server.post("/auth/register", (req, res) => {
  console.log("register endpoint called; request body:");
  console.log(req.body);
  const { email, password, ...rest } = req.body;

  // Kiểm tra xem người dùng đã tồn tại trong cơ sở dữ liệu hay không
  const userExists = userdb.users.some((user) => user.email === email);
  if (userExists) {
    const status = 400;
    const message = "Email already exists";
    res.status(status).json({ status, message });
    return;
  }

  // Lấy danh sách người dùng từ cơ sở dữ liệu
  const users = JSON.parse(fs.readFileSync("./users.json", "UTF-8"));

  // Tạo ID cho người dùng mới
  const userId = users.users.length + 1;

  // Thêm người dùng mới vào mảng users
  users.users.push({ id: userId, email, password, ...rest });

  // Ghi lại cơ sở dữ liệu đã cập nhật
  fs.writeFile("./users.json", JSON.stringify(users), (err) => {
    if (err) {
      const status = 500;
      const message = "Error saving user data";
      res.status(status).json({ status, message });
      return;
    }
  });

  // Tạo token cho người dùng mới
  const access_token = createToken({ email, password });
  console.log("Access Token:" + access_token);

  // Trả về kết quả thành công cùng với token cho người dùng
  res.status(200).json({ access_token });
});

// Login to one of the users from ./users.json
server.post("/auth/login", (req, res) => {
  console.log("login endpoint called; request body:");
  console.log(req.body);
  const { email, password } = req.body;

  const userDbInfo = userdb.users.find((user) => user.email === email);
  console.log(userDbInfo);

  if (!userDbInfo) {
    const status = 400;
    const message = "Incorrect email";
    res.status(status).json({ status, message });
    return;
  }

  if (userDbInfo.password !== password) {
    const status = 400;
    const message = "Incorrect password";
    res.status(status).json({ status, message });
    return;
  }

  const access_token = createToken({ email, password });
  console.log("Access Token:" + access_token);
  res.status(200).json({ access_token, ...userDbInfo });
});

server.use(/^(?!\/auth).*$/, (req, res, next) => {
  const isApiAuth = !API_NOT_AUTH.includes(req?.baseUrl);
  if ((req.headers.authorization === undefined || req.headers.authorization.split(" ")[0] !== "Bearer") && isApiAuth) {
    const status = 401;
    const message = "Error in authorization format";
    res.status(status).json({ status, message });
    return;
  }
  try {
    let verifyTokenResult;
    verifyTokenResult = verifyToken(req?.headers?.authorization?.split(" ")[1]);

    if (verifyTokenResult instanceof Error && isApiAuth) {
      const status = 401;
      const message = "Access token not provided";
      res.status(status).json({ status, message });
      return;
    }
    next();
  } catch (err) {
    const status = 401;
    const message = "Error access_token is revoked";
    res.status(status).json({ status, message });
  }
});

//PUT USER
server.patch("/auth/users/:id", (req, res) => {
  const { email, password, ...rest } = req.body;
  const { id } = req.params;

  // Check if the user ID is a valid integer
  if (isNaN(id)) {
    const status = 400;
    const message = "Invalid user ID";
    res.status(status).json({ status, message });
    return;
  }

  // Find the user by ID
  const userIndex = userdb.users.findIndex((user) => user.id === parseInt(id));
  if (userIndex === -1) {
    const status = 404;
    const message = "User not found";
    res.status(status).json({ status, message });
    return;
  }

  // Update the user's data
  userdb.users[userIndex] = { ...userdb.users[userIndex], ...req.body };

  // Write the updated user data back to the database file
  fs.writeFile("./users.json", JSON.stringify(userdb), (err) => {
    if (err) {
      const status = 500;
      const message = "Error updating user data";
      res.status(status).json({ status, message });
      return;
    }
    const status = 200;
    const message = "User updated successfully";
    res.status(status).json({ status, message });
  });
});

//DELETE USER
server.delete("/auth/users/:id", (req, res) => {
  const { id } = req.params;

  // Check if the user ID is a valid integer
  if (isNaN(id)) {
    const status = 400;
    const message = "Invalid user ID";
    res.status(status).json({ status, message });
    return;
  }

  // Find the index of the user in the array
  const userIndex = userdb.users.findIndex((user) => user.id === parseInt(id));
  if (userIndex === -1) {
    const status = 404;
    const message = "User not found";
    res.status(status).json({ status, message });
    return;
  }

  // Remove the user from the array
  userdb.users.splice(userIndex, 1);

  // Write the updated user data back to the database file
  fs.writeFile("./users.json", JSON.stringify(userdb), (err) => {
    if (err) {
      const status = 500;
      const message = "Error updating user data";
      res.status(status).json({ status, message });
      return;
    }
    const status = 200;
    const message = "User deleted successfully";
    res.status(status).json({ status, message });
  });
});

// GET USERS
server.get("/auth/users", (req, res) => {
  const { email, password, ...rest } = req.body;
  if (req.headers.authorization === undefined || req.headers.authorization.split(" ")[0] !== "Bearer") {
    const status = 401;
    const message = "Error in authorization format";
    res.status(status).json({ status, message });
    return;
  }
  try {
    let verifyTokenResult;
    verifyTokenResult = verifyToken(req?.headers?.authorization?.split(" ")[1]);
    if (verifyTokenResult?.email) {
      const userDbInfo = userdb.users.find((user) => user.email === verifyTokenResult?.email);
      if (userDbInfo.role === 1) {
        const status = 200;
        res.status(status).json(userdb.users);

        return;
      }
    }
    const status = 401;
    const message = "Access token not provided";
    res.status(status).json({ status, message });
    return;
  } catch (err) {
    const status = 401;
    console.log(err);
    const message = "Error access_token is revoked";
    res.status(status).json({ status, message });
  }
  return;
});

//GET PROFILE
server.get("/auth/my-profile", (req, res) => {
  if (req.headers.authorization === undefined || req.headers.authorization.split(" ")[0] !== "Bearer") {
    const status = 401;
    const message = "Error in authorization format";
    res.status(status).json({ status, message });
    return;
  }
  try {
    let verifyTokenResult;
    verifyTokenResult = verifyToken(req?.headers?.authorization?.split(" ")[1]);

    if (verifyTokenResult instanceof Error && isApiAuth) {
      const status = 401;
      const message = "Access token not provided";
      res.status(status).json({ status, message });
      return;
    }

    if (verifyTokenResult?.email) {
      const userDbInfo = userdb.users.find((user) => user.email === verifyTokenResult?.email);
      res.status(200).json({ status: 200, data: { ...userDbInfo } });
      return;
    }
  } catch (err) {
    const status = 401;
    const message = "Error access_token is revoked";
    res.status(status).json({ status, message });
  }
});

router.render = (req, res) => {
  const headers = res.getHeaders();
  const totalCountHeader = headers["x-total-count"];
  if (req.method === "GET" && totalCountHeader) {
    const queryParams = queryString.parse(req._parsedOriginalUrl.query);
    const results = {
      data: res.locals.data,
      pagination: {
        _page: Number.parseInt(queryParams._page) || 1,
        _limit: Number.parseInt(queryParams._limit) || 10,
        _totalRows: Number.parseInt(totalCountHeader),
      },
    };
    return res.jsonp(results);
  }
  return res.jsonp(res.locals.data);
};

server.use(router);

server.listen(8000, () => {
  console.log("Run Auth API Server");
});
