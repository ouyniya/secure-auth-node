#!/bin/sh
set -e

# รอ MySQL พร้อม
echo "Waiting for MySQL..."
until nc -z -v -w30 mysql 3306
do
  echo "Waiting for database connection..."
  sleep 2
done

echo "Running Prisma migrations..."
npx prisma migrate deploy

echo "Running seed..."
npx prisma db seed || true

echo "Starting Node.js application..."
exec node dist/index.js

