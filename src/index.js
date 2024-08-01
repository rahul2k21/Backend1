import dotenv from "dotenv";
import connectDB from "./db/index.js";
import { app } from "./app.js";



dotenv.config({
  path: "./env",
});

connectDB()
  .then(() => {
    app.listen(process.env.PORT || 6000, () => {
      console.log(`server is runnning at the port: ${process.env.PORT}`);
    });
  })

  .catch((err) => {
    console.log("MONGO DB connection failed !!!", err);
  });











// import express from "express";
// const app = express();

// (async () => {
//   try {
//     await mongoose.connect(`${process.env.MONGODB_URI}/${DB_NAME}`);
//     app.on("error", (error) => {
//       console.log("ERRR:", error);
//       throw err;
//     });

//     app.listen(process.env.PORT, () => {
//       console.log(`app is litening on the port $ {process.env.PORT}`);
//     });
//   } catch (error) {
//     console.error("ERROR:", error);
//     throw err;
//   }
// })();
