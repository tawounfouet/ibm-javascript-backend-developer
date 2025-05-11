router.post('/register', async (req, res) => {
    try {
        // Task 1: Connect to `secondChance` in MongoDB through `connectToDatabase` in `db.js`.
        const db = await connectToDatabase();

          
        // Task 2: Access MongoDB `users` collection
        const usersCollection = db.collection('users');
        
        // Task 3: Check if user credentials already exists in the database and throw an error if they do
        const { email, password } = req.body;
        const existingUser = await usersCollection.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ error: 'User already exists' });
        }
        // Task 4: Create a hash to encrypt the password so that it is not readable in the database
        const hashedPassword = await bcrypt.hash(password, 10);
        
        // Task 5: Insert the user into the database
        const newUser = { email, password: hashedPassword };
        await usersCollection.insertOne(newUser);
        
        // Task 6: Create JWT authentication if passwords match with user._id as payload
        const token = jwt.sign({ userId: newUser._id }, process.env.JWT_SECRET);
        
        // Task 7: Log the successful registration using the logger
        logger.info(`User registered successfully: ${email}`);
        
        // Task 8: Return the user email and the token as a JSON
        res.json({ email, token });
        
    } catch (e) {
         return res.status(500).send('Internal server error');
    }
});

router.post('/login', async (req, res) => {
    try {
        // Task 1: Connect to `secondChance` in MongoDB through `connectToDatabase` in `db.js`.
        const db = await connectToDatabase();

        // Task 2: Access MongoDB `users` collection
        const usersCollection = db.collection('users');

        // Task 3: Check for user credentials in database
        const { email, password } = req.body;
        const user = await usersCollection.findOne({ email });
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Task 4: Check if the password matches the encrypted password and send appropriate message on mismatch
        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) {
            return res.status(401).json({ error: 'Incorrect password' });
        }

        // Task 5: Fetch user details from a database
        const { _id, userName, userEmail } = user;

        // Task 6: Create JWT authentication if passwords match with user._id as payload
        const token = jwt.sign({ userId: _id }, process.env.JWT_SECRET);

        // Task 7: Send appropriate message if the user is not found
        res.json({ authtoken: token, userName, userEmail });
    } catch (e) {
         return res.status(500).send('Internal server error');
    }
});

// Task 1: Use the `body`, `validationResult` from `express-validator` for input validation
router.put('/update', [
    body('email').isEmail().normalizeEmail(),
    body('userName').notEmpty(),
    body('password').isLength({ min: 6 }),
], async (req, res) => {
    // Task 2: Validate the input using `validationResult` and return an appropriate message if you detect an error
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    try {
        // Task 3: Check if `email` is present in the header and throw an appropriate error message if it is not present
        const { email } = req.body;
        if (!email) {
            return res.status(400).json({ error: 'Email is required in the header' });
        }

        // Task 4: Connect to MongoDB
        const db = await connectToDatabase();
        const usersCollection = db.collection('users');

        // Task 5: Find the user credentials in database
        const existingUser = await usersCollection.findOne({ email });
        if (!existingUser) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Task 6: Update the user credentials in the database
        await usersCollection.updateOne({ email }, { $set: { ...req.body, updatedAt: new Date() } });

        // Task 7: Create JWT authentication with `user._id` as a payload using the secret key from the .env file
        const token = jwt.sign({ userId: existingUser._id }, process.env.JWT_SECRET);

        res.json({ authtoken: token });
    } catch (e) {
        return res.status(500).send('Internal server error');
    }
});

module.exports = router;
       
