import express from "express";
import users from "./database";
import { v4 as uuid } from "uuid";
import { hash, compare } from "bcrypt";
import jwt from "jsonwebtoken";
import { json } from "stream/consumers";

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
    return res.status(401).json({ message: "Missing authorization headers" });
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
    next();
  });
};

const passwordMatchMiddleware = async (req, res, next) => {
  const { email, password } = req.body;
  const user = users.find((elem) => elem.email === email);
  console.log(user, password);
  const comparePassword = await compare(password, user.password);

  if (!comparePassword) {
    return res.status(401).json({ message: "Wrong email or password" });
  }

  return next();
};

const isAdminMiddleware = (req, res, next) => {
  let authToken = req.headers.authorization;

  const token = authToken.split(" ")[1];

  return jwt.verify(token, "SECRET_KEY", (error, decoded) => {
    const uuid = decoded.sub;

    const user = users.find((elem) => elem.uuid === uuid);

    console.log(uuid);
    if (!user.isAdm) {
      return res.status(403).json({ message: "missing admin permissions" });
    }
    return next();
  });
};

const userUuidExistsMiddleware = (req, res, next) => {
  const uuid = req.params.id;
  const exists = users.find((elem) => elem.uuid === uuid);
  exists ? next() : res.status(404).json({ error: "User not found" });
};

const userUpdateRightsMiddleware = (req, res, next) => {
  const authToken = req.headers.authorization;

  const token = authToken.split(" ")[1];

  return jwt.verify(token, "SECRET_KEY", (error, decoded) => {
    const uuid = decoded.sub;

    const user = users.find((elem) => elem.uuid === uuid);

    console.log(uuid);
    if (user.isAdm || uuid === req.params.id) {
      return next();
    }
    return res
      .status(403)
      .json({ message: "You don't have permission for that" });
  });
};

const createUserService = async (name, email, password, isAdm = true) => {
  const newUser = {
    name: name,
    email: email,
    password: await hash(password, 10),
    isAdm: isAdm,
    createdOn: new Date(),
    updatedOn: new Date(),
    uuid: uuid(),
  };

  const response = {
    ...newUser,
  };

  delete response.password;

  users.push(newUser);

  return [201, response];
};

const listUserService = () => {
  return [200, users];
};

const listEspecificUserService = (uuid) => {
  const user = users.find((elem) => elem.uuid === uuid);
  if (!user) {
    return [400, { error: "userNotFound" }];
  }
  const response = {
    ...user,
  };
  delete response.password;

  return [200, response];
};

const loginService = (email) => {
  const user = users.find((element) => element.email === email);

  const token = jwt.sign({ email }, "SECRET_KEY", {
    expiresIn: "24h",
    subject: user.uuid,
  });

  return [200, { token }];
};

const updateUserService = async (uuid, data) => {
  const index = users.findIndex((elem) => elem.uuid === uuid);
  const actual = users.find((elem) => elem.uuid === uuid);
  delete data.isAdm;
  if (data.password) {
    data.password = await hash(data.password, 10);
  }
  const user = {
    ...actual,
    ...data,
    updatedOn: new Date(),
  };
  const response = {
    ...user,
  };
  delete response.password;
  users[index] = user;
  return [200, response];
};

const getProfileService = (auth) => {
  const token = auth.split(" ")[1];

  return jwt.verify(token, "SECRET_KEY", (error, decoded) => {
    const uuid = decoded.sub;
    console.log(uuid)

    const user = users.find((elem) => elem.uuid === uuid);

    const response = {
      ...user
    }

    delete response.password

    return [200, response]
  })
}

const deleteUserService = (id) => {
  const index = users.findIndex((elem) => elem.uuid === id)
  users.splice(index, 1)
  return [204]
}

const createUserController = async (request, response) => {
  const { name, email, password, isAdm } = request.body;
  const [status, user] = await createUserService(name, email, password, isAdm);

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
  const uuid = req.params.id;
  const [status, response] = listEspecificUserService(uuid);

  return res.status(status).json(response);
};

const updateUserController = async (req, res) => {
  const uuid = req.params.id;
  const [status, response] = await updateUserService(uuid, req.body);

  return res.status(status).json(response);
};

const getProfileController = (req, res) => {
  const [status, response] = getProfileService(req.headers.authorization)
  
  return res.status(status).json(response)
}

const deleteUserController = (req, res) => {
  const [status, response] = deleteUserService(req.params.id)
  return res.status(status).json(response)
}

app.post("/users", userExistsMiddleware, createUserController);
app.get(
  "/users",
  tokenExistsMiddleware,
  tokenIsValidMiddleware,
  isAdminMiddleware,
  listUserController
  );
  app.get("/users/profile", tokenExistsMiddleware, tokenIsValidMiddleware, getProfileController);
app.get(
  "/users/:id",
  tokenExistsMiddleware,
  tokenIsValidMiddleware,
  listEspecificUserController
);
app.post(
  "/login",
  userDoesntExistsMiddleware,
  passwordMatchMiddleware,
  loginController
);
app.patch(
  "/users/:id",
  tokenExistsMiddleware,
  tokenIsValidMiddleware,
  userUuidExistsMiddleware,
  userUpdateRightsMiddleware,
  updateUserController
);
app.delete("/users/:id", tokenExistsMiddleware, tokenIsValidMiddleware, userUuidExistsMiddleware, userUpdateRightsMiddleware, deleteUserController )

const port = 3000;

app.listen(port, () => {
  console.log(`server rodando na porta ${port}`);
});

export default app;
