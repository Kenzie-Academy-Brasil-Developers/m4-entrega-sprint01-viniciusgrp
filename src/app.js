import express from "express";
import users from "./database";
import { v4 as uuid } from "uuid";
import { hash, compare } from "bcrypt";
import jwt from "jsonwebtoken";

const app = express();

app.use(express.json());

const userExistsMiddleware = (req, res, next) => {
  const { email } = req.body;
  const findUser = users.findIndex((elem) => elem.email === email);
  if (findUser !== -1) {
    return res.status(409).json({ message: "User already exists" });
  }
  return next();
};

const userDoesntExistsMiddleware = (req, res, next) => {
  const { email } = req.body;
  const findUser = users.findIndex((elem) => elem.email === email);
  if (findUser === -1) {
    return res.status(409).json({ message: "Wrong email or password" });
  }
  return next();
};

const tokenExistsMiddleware = (req, res, next) => {
  let token = req.headers.authorization;

  if (!token) {
    return res.status(401).json({message: "Missing authorization headers"});
  }

  return next();
};

const tokenIsValidMiddleware = (req, res, next) => {
  let authToken = req.headers.authorization;

  const token = authToken.split(" ")[1];

  return jwt.verify(token, "SECRET_KEY", (error, decoded) => {
    if (error) {
      return res.status(401).json({ message: error.message });
      }
      next()
  });
};

const passwordMatchMiddleware = async (req, res, next) => {
  const { email, password } = req.body;
  const user = users.find((elem) => elem.email === email);
  console.log(user, password);
  const comparePassword = await compare(password, user.password);

  if (!comparePassword) {
    return res.status(401).json({ error: "Wrong email or password" });
  }

  return next();
};

const isAdminMiddleware = (req, res, next) => {
    let authToken = req.headers.authorization;
  
    const token = authToken.split(" ")[1];
  
    return jwt.verify(token, "SECRET_KEY", (error, decoded) => {
          const uuid = decoded.sub

        const user = users.find((elem) => elem.uuid === uuid)

        console.log(uuid)
        if (!user.isAdmin) {
            return res.status(403).json({ message: "missing admin permissions" })
        }
        return next()
    });
  };

const createUserService = async (name, email, password, isAdmin) => {
  const newUser = {
    name: name,
    email: email,
    password: await hash(password, 10),
    isAdmin: isAdmin,
    createdOn: new Date(),
    updatedOn: new Date(),
    uuid: uuid(),
  };

    const response = {
      ...newUser
    };
    
    delete response.password

  users.push(newUser);

  return [201, response];
};

const listUserService = () => {
  return [201, users];
};

const listEspecificUserService = (uuid) => {
    const user = users.find((elem) => elem.uuid === uuid)
    if (!user) {
        return [400, {error: "userNotFound"}]
    }
    const response = {
        ...user
    }
    delete response.password

    return [200, response]
}

const loginService = (email) => {
    const user = users.find((element) => element.email === email);

  const token = jwt.sign({ email }, "SECRET_KEY", { expiresIn: "24h", subject: user.uuid });

  return [200, { token }];
};

const createUserController = async (request, response) => {
  const { name, email, password, isAdmin } = request.body;
  const [status, user] = await createUserService(name, email, password, isAdmin);

  return response.status(status).json(user);
};

const listUserController = (req, res) => {
  const [status, users] = listUserService();
  return res.status(status).json(users);
};

const loginController = (req, res) => {
  const { email } = req.body;
  const [status, token] = loginService(email);

  return res.status(status).json(token);
};

const listEspecificUserController = (req, res) => {
    const uuid = req.params.id
    const [status, response] = listEspecificUserService(uuid)

    return res.status(status).json(response)
}

app.post("/users", userExistsMiddleware, createUserController);
app.get("/users", tokenExistsMiddleware, tokenIsValidMiddleware, isAdminMiddleware, listUserController);
app.get("/users/:id", tokenExistsMiddleware, tokenIsValidMiddleware, listEspecificUserController );
app.post("/login", userDoesntExistsMiddleware, passwordMatchMiddleware, loginController);

const port = 3000;

app.listen(port, () => {
  console.log(`server rodando na porta ${port}`);
});

export default app;
