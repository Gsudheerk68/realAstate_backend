// ============================================================
// PlotLine — Admin promotion script
// ============================================================
// Promotes an existing user to the 'admin' role so they can log in
// and access the admin dashboard at /admin.html.
//
// Usage:
//   node createAdmin.js user@example.com
//
// The user must have already signed up normally (as a buyer or
// seller) through the app before running this script.

const mongoose = require('mongoose');
const dotenv = require('dotenv');
dotenv.config();

const mongoUri = process.env.MONGODB_URI || 'mongodb://localhost:27017/plotline';

const UserSchema = new mongoose.Schema({
  name: String,
  email: String,
  phone: String,
  password: String,
  role: { type: String, enum: ['buyer', 'seller', 'admin'] },
  isActive: { type: Boolean, default: true }
});

const User = mongoose.model('User', UserSchema);

async function main() {
  const email = process.argv[2];

  if (!email) {
    console.error('Usage: node createAdmin.js <email>');
    process.exit(1);
  }

  await mongoose.connect(mongoUri);

  const user = await User.findOne({ email: email.toLowerCase() });
  if (!user) {
    console.error(`No user found with email "${email}". Sign up through the app first, then run this script.`);
    process.exit(1);
  }

  user.role = 'admin';
  await user.save();

  console.log(`✓ ${user.name} <${user.email}> is now an admin. They can log in normally and will land on /admin.html.`);
  await mongoose.disconnect();
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
