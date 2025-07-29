-- Users table
CREATE TABLE IF NOT EXISTS "Users" (
    id SERIAL PRIMARY KEY,
    "firstName" VARCHAR(255) NOT NULL,
    "lastName" VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    role VARCHAR(20) NOT NULL DEFAULT 'teacher', -- 'teacher', 'headmaster', 'admin'
    "periodsPerWeek" INTEGER NOT NULL DEFAULT 0,
    "periodsPerDay" JSON NOT NULL DEFAULT '{"Sun":0,"Mon":0,"Tue":0,"Wed":0,"Thu":0,"Fri":0,"Sat":0}',
    "resetPasswordCode" VARCHAR(255),
    "resetPasswordExpires" TIMESTAMP,
    "createdAt" TIMESTAMP NOT NULL DEFAULT NOW(),
    "updatedAt" TIMESTAMP NOT NULL DEFAULT NOW()
);

-- TeachingRecords table
CREATE TABLE IF NOT EXISTS "TeachingRecords" (
    id SERIAL PRIMARY KEY,
    date DATE NOT NULL,
    class VARCHAR(255) NOT NULL,
    subject VARCHAR(255) NOT NULL,
    period VARCHAR(255) NOT NULL,
    topic VARCHAR(255) NOT NULL,
    subtopic VARCHAR(255),
    "teacherWork" TEXT NOT NULL,
    "studentWork" TEXT NOT NULL,
    remarks TEXT,
    status VARCHAR(20) DEFAULT 'draft', -- 'draft', 'submitted', 'reviewed', 'rejected'
    feedback TEXT,
    rating INTEGER CHECK (rating >= 1 AND rating <= 5),
    "userId" INTEGER NOT NULL REFERENCES "Users"(id) ON DELETE CASCADE,
    "createdAt" TIMESTAMP NOT NULL DEFAULT NOW(),
    "updatedAt" TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Index for faster lookups by user and date
CREATE INDEX IF NOT EXISTS idx_teachingrecords_userid_date ON "TeachingRecords" ("userId", date); 