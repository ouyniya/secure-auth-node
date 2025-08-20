const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcryptjs');

const prisma = new PrismaClient();

async function createAdminUser() {
  try {
    const username = 'admin';
    const email = 'admin@financial-institution.com';
    const fullName = 'System Administrator';
    const password = process.env.ADMIN_PASSWORD || 'SecureAdmin123!';

    // Check if admin user already exists
    const existingUser = await prisma.user.findFirst({
      where: { OR: [{ username }, { email }] },
    });

    if (existingUser) {
      console.log('Admin user already exists');
      return;
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 12);

    // Create admin user
    const user = await prisma.user.create({
      data: {
        username,
        email,
        fullName,
        hashedPassword,
        isPrivileged: false, // TODO: change to true after testing
        passwordChangedAt: new Date(),
      },
    });

    // Save initial password to history
    await prisma.passwordHistory.create({
      data: {
        userId: user.id,
        hashedPassword,
      },
    });

    console.log('Admin user created successfully');
    console.log(`Username: ${username}`);
    console.log(`Password: ${password}`);
    console.log(
      'Please change the default password immediately after first login',
    );
  } catch (error) {
    console.error('Error creating admin user:', error);
  } finally {
    await prisma.$disconnect();
  }
}

createAdminUser();
