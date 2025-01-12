import express from 'express';
import bodyParser from 'body-parser';
import session from 'express-session';
import passport from 'passport';
import { Strategy } from 'passport-local';
import env from 'dotenv';
import pg from 'pg';
import pgSession from 'connect-pg-simple';
import bcrypt from "bcrypt";
import multer from 'multer';
import fs from 'fs';
import axios from 'axios';

//port and express declaration
const port=3000;
const app=express();

const saltRounds=10;
env.config()
const db= new pg.Client({
    user:process.env.DATABASE_USER,
    host: process.env.DATABASE_HOST,
    database: process.env.DATABASE_NAME,
    password:process.env.DATABASE_PASSWORD,
    port: process.env.DATABASE_PORT,
    
});

db.connect();

//image path added
const newpath="./public/images/";
if (!fs.existsSync(newpath)) {
    fs.mkdirSync(newpath, { recursive: true });
}

const pgStore = pgSession(session);  
const sessionStore = new pgStore({
    pool: db,
    tableName: 'session',
});


app.use(express.static('public'));
app.use(bodyParser.urlencoded({extended:true}))

app.use(session(
    {
        secret:process.env.SESSION_SECRET,
        saveUninitialized:true,
        resave:false,
        cookie:{ maxAge: 3* 24 * 60 * 60 * 1000 }
    }
));

app.use(passport.initialize());
app.use(passport.session());

//multer set up
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'public/images/'); // Save images to 'uploads/' folder
    },
    filename: (req, file, cb) => {
        console.log(file.originalname)
        cb(null, `${Date.now()}-${file.originalname}`); // Unique file name
    },
});

const upload = multer({ storage });

app.get('/',async(req,res)=>{

    console.log('connection established');
    if (req.isAuthenticated()){
        const result = await db.query(`
            SELECT p.id, p.productname, p.price, p.description, p.img, 
                   CASE WHEN f.userid IS NOT NULL THEN true ELSE false END AS isFavorited
            FROM product p
            LEFT JOIN favorites f ON p.id = f.productid AND f.userid = $1;
        `, [req.user.id]);
        
         res.render('main.ejs',{
            loggedIn:true,
            user:req.user,
            product:result.rows});
        }
        else{
        const result= await db.query('SELECT * FROM public.product');
        res.render('main.ejs',{product:result.rows});
    }
})

app.get('/login',(req,res)=>{
        res.render('login.ejs',{error:''});
});
    
app.get('/signup',(req,res)=>{
    res.render('signup.ejs');
});

app.post('/login', (req, res, next) => {
    passport.authenticate('local', (err, user, info) => {
        if (err) {
            console.error('Authentication error:', err);
            return res.render('login.ejs', { error: 'An unexpected error occurred. Please try again.' });
        }

        if (!user) {
            console.warn('Login failed:', info?.message || 'Invalid email or password');
            return res.render('signup.ejs', { error: 'Invalid email or password. try signup' });
        }

        req.logIn(user, (err) => {
            if (err) {
                console.error('Error during login:', err);
                return res.render('login.ejs', { error: 'An unexpected error occurred. Please try again.' });
            }

            if (user.role === 'admin') {
                console.log('Admin user logged in.');
                return res.redirect('/admin');
            } else {
                console.log('Regular user logged in.');
                return res.redirect('/');
            }
        });
    })(req, res, next);
});



app.get('/logout', (req, res, next) => {
    req.logout((err) => {
        if (err) {
            return res.json({message:'error occured'}); // Handle errors if any occur
        }
        req.session.destroy((err) => {
            if (err) {
                console.error('Error destroying session:', err);
                return res.status(500).send('Error logging out');
            }
            res.redirect('/'); // Redirect to the login page or homepage
        });
    });
});

//partial ok
app.post('/signup',async(req,res)=>{

    const email=req.body.email;
    const password=req.body.password;
    const username=req.body.username;
    const captitalizeUserName=username.charAt(0).toUpperCase()+username.slice(1)
    const confirmPassword=req.body.confirmpassword;
        if(password===confirmPassword){
                bcrypt.hash(password,saltRounds,async function(err,newhash){
                    try{
                        console.log();
                        
                        const userCredential=await db.query('INSERT INTO users (email,password,displayName) values($1,$2,$3)',[email,newhash,captitalizeUserName])
                        const result= await db.query('SELECT * FROM users where email=$1',[email])
                        const user= result.rows[0]
                        req.login(user,(err)=>{
                            res.redirect('/');
                        })
                    }catch(err){
                        if(err.message=='duplicate key value violates unique constraint "users_email_key"'){
                            res.render('signup.ejs',{error:'Already have a account try logging in'})
                            console.log(err.message);}} 
                    })
            
            }
        else{
            res.render('signup.ejs',{error:'password mismatch try again!'})}
});


passport.use(new Strategy({ usernameField: 'email' }, async function verify(email, password, cb) {
    try {
        // Query the database for the user by email
        const result = await db.query('SELECT * FROM users WHERE email=$1', [email]);

        // Check if a user exists
        if (result.rows.length === 0) {
            return cb(null, false, { message: 'Incorrect email or password.' });
        }

        const user = result.rows[0];
        const storedPassword = user.password;

        // Compare the provided password with the stored hashed password
        bcrypt.compare(password, storedPassword, (err, isMatch) => {
            if (err) {
                return cb(err); // Pass error to Passport
            }

            if (isMatch) {
                return cb(null, user); // Password is correct; pass the user to Passport
            } else {
                return cb(null, false, { message: 'Incorrect email or password.' });
            }
        });
    } catch (err) {
        console.error('Error verifying user:', err);
        return cb(err); // Pass the error to Passport
    }
}));

//admin side

app.get('/admin',async (req, res) => {
    if(req.isAuthenticated() && req.user.role=='admin'){
        const result= await db.query('SELECT * FROM public.product');
    console.log(req.body);
        res.render('admin.ejs',{product:result.rows})
    }
    else{
        res.send('not authorized');
    }
});

app.get('/adminpost',(req,res)=>{
    res.render('adminpost.ejs',{
        action:'Submit'
    })
})



app.post('/adminpost', upload.single('img'), async (req, res) => {
    const {itemname, productname, price , description} = req.body;
   
    try {
        // Validate Input
        if (!itemname ||!productname|| !price || !description ||!req.file ) {
            return res.status(400).json({ error: 'You forgot something' });
        }
    
        // SQL Query to Insert Product
        const query = `
            INSERT INTO product (itemname, productname, price , description, img)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING *;
        `;
        const values = [
            itemname,
            productname,
            parseFloat(price), // Ensure price is a float
            description || null,
            `images/${req.file.filename}`, // Path to uploaded file
        ];
    
        // Execute Query
        const result = await db.query(query, values);
        res.redirect("/admin")
    
        // Respond with Success
        // res.status(201).json({ message: 'Product added successfully', product: result.rows[0] });
    } catch (err) {
        console.error('Error saving product:', err);
        res.status(500).json({ error: err.message});
    }
    });
app.get('/adminedit/:id',async(req,res)=>{
    const id=req.params.id;
    const result=await db.query('SELECT * FROM product WHERE id=$1',[id]);
    res.render('adminpost.ejs',{
        action:'update post',
        post:result.rows[0],
    })

})
app.get('/admindelete/:id', async (req, res) => {
    const id = req.params.id;
    console.log(req.user);
    

    try {
        // Fetch the image path for the product
        const productQuery = await db.query('SELECT img FROM product WHERE id=$1', [id]);
        if (productQuery.rows.length === 0) {
            return res.status(404).send('Product not found');
        }

        const oldImagePath = `public/${productQuery.rows[0].img}`;
        
        // Delete the product from the database
        await db.query('DELETE FROM product WHERE id=$1', [id]);

        // Check and delete the associated image file
        if (fs.existsSync(oldImagePath)) {
            fs.unlinkSync(oldImagePath);
        }

        // Redirect to admin page
        res.redirect('/admin');
    } catch (err) {
        console.error('Error deleting product:', err);
        res.status(500).send('Internal server error');
    }
});

app.post('/adminpost/:id', upload.single('img'), async (req, res) => {
    const id = req.params.id;
    const { itemname, productname, price, description } = req.body;
    const imageFile = req.file;

    try {
        // Fetch the current product details
        const productCheckQuery = 'SELECT * FROM product WHERE id = $1';
        const productCheckResult = await db.query(productCheckQuery, [id]);

        if (productCheckResult.rows.length === 0) {
            return res.status(404).json({ error: 'Product not found' });
        }

        const existingProduct = productCheckResult.rows[0];
        if (imageFile && existingProduct.img) {
            const oldImagePath = `public/${existingProduct.img}`;
            if (fs.existsSync(oldImagePath)) {
                fs.unlinkSync(oldImagePath);
            }
        }

        // Use provided values or fallback to existing values
        const updatedItemName = itemname || existingProduct.itemname;
        const updatedProductName = productname || existingProduct.productname;
        const updatedPrice = price || existingProduct.price;
        const updatedDescription = description || existingProduct.description;
        const updatedImagePath = imageFile
            ? `images/${imageFile.filename}`
            : existingProduct.img;

        // Update the database
        const updateQuery = `
            UPDATE product 
            SET itemname = $1, productname = $2, price = $3, description = $4, img = $5
            WHERE id = $6
            RETURNING *;
        `;
        const values = [
            updatedItemName,
            updatedProductName,
            updatedPrice,
            updatedDescription,
            updatedImagePath,
            id,
        ];

        const result = await db.query(updateQuery, values);
        res.redirect('/admin')
        // res.status(200).json({
        //     message: 'Product updated successfully',
        //     product: result.rows[0],
        // });
    } catch (err) {
        console.error('Error updating product:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.get('/changepassword', (req, res) => {
    res.send(`
        <h1>Change Password</h1>
        <form action="/changepassword" method="POST">
            <label for="currentPassword">Current Password:</label>
            <input type="password" id="currentPassword" name="currentPassword" required>
            <br>
            <label for="newPassword">New Password:</label>
            <input type="password" id="newPassword" name="newPassword" required>
            <br>
            <label for="confirmPassword">Confirm New Password:</label>
            <input type="password" id="confirmPassword" name="confirmPassword" required>
            <br>
            <button type="submit">Change Password</button>
        </form>
    `);
});

app.post('/changepassword', async (req, res) => {
    const { currentPassword, newPassword, confirmPassword } = req.body;

    if (!req.isAuthenticated()) {
        return res.redirect('/login'); // Ensure the user is authenticated
    }

    // Retrieve email from authenticated user
    const email = req.user.email;

    // Add the password change logic here (validate, hash, update, etc.)
    try {
        const userQuery = await db.query('SELECT * FROM users WHERE email = $1', [email]);
        const user = userQuery.rows[0];

        if (!user) {
            return res.status(404).send('User not found.');
        }

        const isMatch = await bcrypt.compare(currentPassword, user.password);
        if (!isMatch) {
            return res.status(400).send('Current password is incorrect.');
        }

        if (newPassword !== confirmPassword) {
            return res.status(400).send('New passwords do not match.');
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);
        await db.query('UPDATE users SET password = $1 WHERE email = $2', [hashedPassword, email]);
        res.redirect('/')
    } catch (err) {
        console.error(err);
        res.status(500).send('An error occurred.');
    }
});


app.get('/cart/:id', async (req, res) => {
    if (req.isAuthenticated()) {
        const user = req.user; // The authenticated user
        const productId = req.params.id; // Product ID from the route parameter

        try {
            // Fetch the product details from the product table
            const productResponse = await db.query('SELECT * FROM product WHERE id = $1', [productId]);
            const product = productResponse.rows[0];

            if (!product) {
                return res.status(404).send('Product not found.');
            }

            // Check if the product is already in the user's cart
            const duplicateCheck = await db.query(
                'SELECT * FROM cart WHERE userid = $1 AND productid = $2',
                [user.id, productId]
            );

            if (duplicateCheck.rows.length > 0) {
                return res.status(400).json('This item is already in your cart.');
            }

            // Insert the product into the cart
            await db.query(
                'INSERT INTO cart (userid, productid, quantity) VALUES ($1, $2, $3)',
                [user.id, productId, 1] // Default quantity is 1
            );
            res.redirect('/')
            // res.status(200).json('item added')// Redirect the user back to the homepage
        } catch (err) {
            console.error('Error adding to cart:', err);
            res.status(500).send('An error occurred while adding the item to your cart.');
        }
    } else {
        res.redirect('/login'); // Redirect unauthenticated users to the login page
    }
});



app.get('/cartlist', async (req, res) => {
    if (req.isAuthenticated()) {
        try {
            const userId = req.user.id; // Get the authenticated user's ID
            
            // Fetch cart data along with product details
            const response = await db.query(
                `SELECT c.id AS cart_id,p.id, p.productname, p.price, p.description, p.img, c.quantity, c.created
                 FROM cart c
                 INNER JOIN product p ON c.productid = p.id
                 WHERE c.userid = $1`,
                [userId]
            );

            const cartData = response.rows;
            console.log(`Cart items: ${cartData.length}`);
            console.log(cartData);
            
            // Render the cart list page and pass the cart data

            res.render('cartlist.ejs', { cartdata: cartData });
        } catch (error) {
            console.error('Error fetching cart data:', error);
            res.status(500).send('An error occurred while fetching your cart.');
        }
    } else {
        res.redirect('/login'); // Redirect unauthenticated users to the login page
    }
});


app.get('/cartremove/:id', async (req, res) => {
    if(req.isAuthenticated()){
        const cartId = req.params.id; // The cart item ID to remove
        const userId = req.user.id; // Get the authenticated user's ID

    try {
        // Check if the cart item exists for the user
        const response = await db.query('SELECT * FROM cart WHERE id = $1 AND userid = $2', [cartId, userId]);
        console.log(response.rows);
        
        console.log(`Cart ID: ${cartId}, User ID: ${userId}`);
        if (response.rows.length > 0) {
            // If the cart item exists, delete it
            await db.query('DELETE FROM cart WHERE id = $1 AND userid = $2', [cartId, userId]);
            res.redirect('/cartlist'); // Redirect to the cart list page
        } else {
            res.status(404).send('Cart item not found or you do not have permission to delete it.');
        }
    } catch (err) {
        console.error('Error removing item from cart:', err);
        res.status(500).send('An error occurred while removing the item from your cart.');
    }
    }
    
});

passport.serializeUser((user,cb)=>{
    cb(null,user)
})
passport.deserializeUser((user,cb)=>{
    cb(null,user)
})
app.listen(port,()=>console.log(`listening to ${port}`))