-- ============================================================
--  Job & Internship Scam Detection System — Database Schema
-- ============================================================

CREATE DATABASE IF NOT EXISTS scam_detection_db;
USE scam_detection_db;
-- ─────────────────────────────────────────────
-- 1. USERS  (students + admins)
-- ─────────────────────────────────────────────
CREATE TABLE Users (
    user_id       INT AUTO_INCREMENT PRIMARY KEY,
    full_name     VARCHAR(100) NOT NULL,
    email         VARCHAR(150) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    phone         VARCHAR(15) UNIQUE,
    role          ENUM('student', 'admin') DEFAULT 'student',
    college       VARCHAR(150),
    created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT chk_email CHECK (email LIKE '%@%.%')
);

-- ─────────────────────────────────────────────
-- 2. COMPANIES / RECRUITERS
-- ─────────────────────────────────────────────
CREATE TABLE Companies (
    company_id      INT AUTO_INCREMENT PRIMARY KEY,
    company_name    VARCHAR(150) NOT NULL,
    website         VARCHAR(255),
    contact_email   VARCHAR(150),
    contact_phone   VARCHAR(15),
    industry        VARCHAR(100),
    address         TEXT,
    is_verified     BOOLEAN DEFAULT FALSE,
    added_by        INT,                          -- admin user_id
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (added_by) REFERENCES Users(user_id) ON DELETE SET NULL
);

-- ─────────────────────────────────────────────
-- 3. JOB POSTINGS
-- ─────────────────────────────────────────────
CREATE TABLE Job_Postings (
    job_id          INT AUTO_INCREMENT PRIMARY KEY,
    title           VARCHAR(200) NOT NULL,
    description     TEXT,
    company_id      INT NOT NULL,
    posted_by       INT,                          -- user who submitted
    job_type        ENUM('internship', 'full-time', 'part-time', 'contract') NOT NULL,
    location        VARCHAR(150),
    salary_range    VARCHAR(100),
    application_url VARCHAR(255),
    deadline        DATE,
    status          ENUM('active', 'closed', 'flagged', 'removed') DEFAULT 'active',
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (company_id) REFERENCES Companies(company_id) ON DELETE CASCADE,
    FOREIGN KEY (posted_by)  REFERENCES Users(user_id)        ON DELETE SET NULL
);

-- ─────────────────────────────────────────────
-- 4. REPORTS  (user-submitted scam reports)
-- ─────────────────────────────────────────────
CREATE TABLE Reports (
    report_id       INT AUTO_INCREMENT PRIMARY KEY,
    job_id          INT,
    company_id      INT,
    reported_by     INT NOT NULL,
    reason          ENUM(
                        'fake_company',
                        'asked_for_money',
                        'no_response_after_offer',
                        'misleading_description',
                        'phishing_link',
                        'other'
                    ) NOT NULL,
    description     TEXT,
    evidence_url    VARCHAR(255),                 -- screenshot link / Drive URL
    status          ENUM('pending', 'reviewed', 'resolved', 'dismissed') DEFAULT 'pending',
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (job_id)      REFERENCES Job_Postings(job_id)  ON DELETE SET NULL,
    FOREIGN KEY (company_id)  REFERENCES Companies(company_id) ON DELETE SET NULL,
    FOREIGN KEY (reported_by) REFERENCES Users(user_id)        ON DELETE CASCADE,
    CONSTRAINT chk_target CHECK (job_id IS NOT NULL OR company_id IS NOT NULL)
);

-- ─────────────────────────────────────────────
-- 5. VERIFICATION  (admin review log)
-- ─────────────────────────────────────────────
CREATE TABLE Verification (
    verification_id  INT AUTO_INCREMENT PRIMARY KEY,
    entity_type      ENUM('company', 'job_posting') NOT NULL,
    entity_id        INT NOT NULL,               -- company_id OR job_id
    verified_by      INT,                        -- admin user_id
    status           ENUM('pending', 'verified', 'flagged', 'rejected') DEFAULT 'pending',
    notes            TEXT,
    verified_at      TIMESTAMP,
    created_at       TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (verified_by) REFERENCES Users(user_id) ON DELETE SET NULL
);

-- ─────────────────────────────────────────────
-- 6. REVIEWS / FEEDBACK
-- ─────────────────────────────────────────────
CREATE TABLE Reviews (
    review_id    INT AUTO_INCREMENT PRIMARY KEY,
    job_id       INT,
    company_id   INT,
    reviewed_by  INT NOT NULL,
    rating       TINYINT NOT NULL,               -- 1 to 5
    title        VARCHAR(200),
    body         TEXT,
    is_anonymous BOOLEAN DEFAULT FALSE,
    created_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (job_id)      REFERENCES Job_Postings(job_id)  ON DELETE SET NULL,
    FOREIGN KEY (company_id)  REFERENCES Companies(company_id) ON DELETE SET NULL,
    FOREIGN KEY (reviewed_by) REFERENCES Users(user_id)        ON DELETE CASCADE,
    CONSTRAINT chk_rating      CHECK (rating BETWEEN 1 AND 5),
    CONSTRAINT chk_review_target CHECK (job_id IS NOT NULL OR company_id IS NOT NULL)
);


-- ============================================================
-- TRIGGERS
-- ============================================================

DELIMITER $$

-- 1. Prevent duplicate report by same user for same job
CREATE TRIGGER prevent_duplicate_report
BEFORE INSERT ON Reports
FOR EACH ROW
BEGIN
    IF NEW.job_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM Reports
        WHERE job_id = NEW.job_id
        AND reported_by = NEW.reported_by
    ) THEN
        SIGNAL SQLSTATE '45000'
        SET MESSAGE_TEXT = 'You have already reported this job posting.';
    END IF;
END$$

-- 2. Auto-flag job when reports >= 3
CREATE TRIGGER auto_flag_job
AFTER INSERT ON Reports
FOR EACH ROW
BEGIN
    DECLARE cnt INT;

    IF NEW.job_id IS NOT NULL THEN
        SELECT COUNT(*) INTO cnt
        FROM Reports
        WHERE job_id = NEW.job_id;

        IF cnt >= 3 THEN
            UPDATE Job_Postings
            SET status = 'flagged'
            WHERE job_id = NEW.job_id;
        END IF;
    END IF;
END$$

-- 3. Set default status to pending
CREATE TRIGGER set_default_report_status
BEFORE INSERT ON Reports
FOR EACH ROW
BEGIN
    IF NEW.status IS NULL OR NEW.status = '' THEN
        SET NEW.status = 'pending';
    END IF;
END$$

DELIMITER ;

-- ============================================================
-- STORED PROCEDURES
-- ============================================================

DELIMITER $$

-- 1. Submit report
CREATE PROCEDURE submit_report(
    IN p_jid INT,
    IN p_uid INT,
    IN p_reason VARCHAR(50),
    IN p_description TEXT
)
BEGIN
    INSERT INTO Reports (job_id, reported_by, reason, description)
    VALUES (p_jid, p_uid, p_reason, p_description);

    SELECT CONCAT('Report submitted for Job ID ', p_jid) AS message;
END$$

-- 2. Get flagged jobs
CREATE PROCEDURE get_flagged_jobs()
BEGIN
    SELECT 
        jp.job_id,
        jp.title,
        c.company_name,
        COUNT(r.report_id) AS total_reports
    FROM Job_Postings jp
    JOIN Companies c ON c.company_id = jp.company_id
    LEFT JOIN Reports r ON r.job_id = jp.job_id
    WHERE jp.status = 'flagged'
    GROUP BY jp.job_id, jp.title, c.company_name;
END$$

-- 3. Verify company + log
CREATE PROCEDURE verify_company(
    IN p_company_id INT,
    IN p_admin_id INT,
    IN p_status VARCHAR(20),
    IN p_note TEXT
)
BEGIN
    -- Update company verification
    UPDATE Companies
    SET is_verified = (p_status = 'verified')
    WHERE company_id = p_company_id;

    -- Insert log
    INSERT INTO Verification
    (entity_type, entity_id, verified_by, status, notes, verified_at)
    VALUES
    ('company', p_company_id, p_admin_id, p_status, p_note, NOW());

    SELECT CONCAT('Company ', p_company_id, ' marked as ', p_status) AS message;
END$$

DELIMITER ;

-- ============================================================
-- FUNCTIONS
-- ============================================================

DELIMITER $$

-- 1. Get report count
CREATE FUNCTION get_report_count(p_job_id INT)
RETURNS INT
DETERMINISTIC
BEGIN
    DECLARE total INT;

    SELECT COUNT(*) INTO total
    FROM Reports
    WHERE job_id = p_job_id;

    RETURN total;
END$$

-- 2. Get average rating
CREATE FUNCTION get_avg_company_rating(p_company_id INT)
RETURNS DECIMAL(4,2)
DETERMINISTIC
BEGIN
    DECLARE avg_r DECIMAL(4,2);

    SELECT AVG(rating) INTO avg_r
    FROM Reviews
    WHERE company_id = p_company_id;

    RETURN avg_r;
END$$

DELIMITER ;

-- ============================================================
--  SAMPLE / SEED DATA
-- ============================================================

-- Users
INSERT INTO Users (full_name, email, password_hash, phone, role, college) VALUES
('Admin User',   'admin@scamdetect.in',  'hashed_admin_pw',  '9000000001', 'admin',   NULL),
('Priya Sharma', 'priya@college.edu',    'hashed_pw_1',      '9000000002', 'student', 'IIT Delhi'),
('Rahul Verma',  'rahul@college.edu',    'hashed_pw_2',      '9000000003', 'student', 'NIT Kurukshetra'),
('Sneha Rao',    'sneha@college.edu',    'hashed_pw_3',      '9000000004', 'student', 'BITS Pilani');

-- Companies
INSERT INTO Companies (company_name, website, contact_email, industry, is_verified, added_by) VALUES
('TechCorp India',     'https://techcorp.in',     'hr@techcorp.in',     'Technology',  TRUE,  1),
('QuickHire Jobs',     'https://quickhire.fake',  'contact@qh.fake',    'Recruitment', FALSE, 1),
('InnovateSoft',       'https://innovatesoft.io', 'jobs@innovate.io',   'Software',    TRUE,  1),
('FakeMoney Startup',  NULL,                       'scam@fakemoney.xyz', 'Finance',     FALSE, 1);

-- Job Postings
INSERT INTO Job_Postings (title, description, company_id, posted_by, job_type, location, salary_range, deadline, status) VALUES
('Frontend Intern',       'React.js internship for 3 months',         1, 1, 'internship',  'Remote',          '5000-8000/mo',  '2025-06-30', 'active'),
('Backend Developer',     'Node.js + MySQL full stack role',           3, 1, 'full-time',   'Bangalore',       '6-10 LPA',      '2025-07-15', 'active'),
('Data Entry Work',       'Easy money from home, no skills needed',   2, 1, 'part-time',   'Work From Home',  '30000/mo',      '2025-05-01', 'flagged'),
('Investment Consultant', 'Guaranteed returns, join our team!',       4, 1, 'contract',    'Online',          '50000/mo',      '2025-04-30', 'flagged');

-- Reports
INSERT INTO Reports (job_id, reported_by, reason, description, status) VALUES
(3, 2, 'asked_for_money',         'They asked for ₹2000 registration fee before joining.', 'pending'),
(4, 3, 'fake_company',            'Company website does not exist. Phone goes unanswered.', 'reviewed'),
(3, 4, 'misleading_description',  'Promised ₹30k but actual work was unpaid spam sharing.', 'pending');

-- Verification
INSERT INTO Verification (entity_type, entity_id, verified_by, status, notes, verified_at) VALUES
('company',      1, 1, 'verified', 'GST and LinkedIn checked. Legitimate.',    NOW()),
('company',      3, 1, 'verified', 'Registered on MCA portal. All clear.',     NOW()),
('company',      2, 1, 'flagged',  'No valid address. Domain registered 2 days ago.', NOW()),
('company',      4, 1, 'rejected', 'Fraudulent. Reported by 5+ students.',     NOW()),
('job_posting',  3, 1, 'flagged',  'Multiple reports of money extortion.',     NOW()),
('job_posting',  4, 1, 'flagged',  'Classic investment scam pattern.',         NOW());

-- Reviews
INSERT INTO Reviews (job_id, company_id, reviewed_by, rating, title, body, is_anonymous) VALUES
(1, 1, 2, 5, 'Great internship!',       'Learned React and got a stipend on time. Highly recommend.', FALSE),
(2, 3, 3, 4, 'Good experience',         'Solid team, good mentorship. Pay could be better.',          FALSE),
(3, 2, 4, 1, 'Complete scam',           'Asked for money and then blocked me. Stay away!',            TRUE),
(4, 4, 2, 1, 'Fraud company',           'This is a ponzi scheme disguised as a job offer.',           TRUE);

-- ============================================================
--  USEFUL QUERIES
-- ============================================================

-- Q1: All flagged job postings with company name
-- SELECT jp.title, c.company_name, jp.status
-- FROM Job_Postings jp
-- JOIN Companies c ON jp.company_id = c.company_id
-- WHERE jp.status = 'flagged';

-- Q2: Number of reports per job posting
-- SELECT jp.title, COUNT(r.report_id) AS report_count
-- FROM Job_Postings jp
-- LEFT JOIN Reports r ON jp.job_id = r.job_id
-- GROUP BY jp.job_id
-- ORDER BY report_count DESC;

-- Q3: Companies with average rating below 2
-- SELECT c.company_name, AVG(rv.rating) AS avg_rating
-- FROM Companies c
-- JOIN Reviews rv ON c.company_id = rv.company_id
-- GROUP BY c.company_id
-- HAVING avg_rating < 2;

-- Q4: All pending reports with reporter name and job title
-- SELECT u.full_name, jp.title, r.reason, r.created_at
-- FROM Reports r
-- JOIN Users u ON r.reported_by = u.user_id
-- JOIN Job_Postings jp ON r.job_id = jp.job_id
-- WHERE r.status = 'pending';

-- Q5: Unverified companies that have active job postings
-- SELECT c.company_name, jp.title
-- FROM Companies c
-- JOIN Job_Postings jp ON c.company_id = jp.company_id
-- WHERE c.is_verified = FALSE AND jp.status = 'active';
