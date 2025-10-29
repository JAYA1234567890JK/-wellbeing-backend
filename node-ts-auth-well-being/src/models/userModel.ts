import mongoose, { Schema, type InferSchemaType, Model } from "mongoose";
import bcrypt from "bcryptjs";

const userSchema = new Schema(
  {
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
  },
  { timestamps: true }
);

// Hash password before save
userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

// Define password compare method
userSchema.methods.matchPassword = async function (enteredPassword: string) {
  return await bcrypt.compare(enteredPassword, this.password);
};

// Infer TypeScript type from schema
export type IUser = InferSchemaType<typeof userSchema> & {
  matchPassword(enteredPassword: string): Promise<boolean>;
};

// Create the model with proper typing
const User: Model<IUser> = mongoose.model<IUser>("User", userSchema);
export default User;
