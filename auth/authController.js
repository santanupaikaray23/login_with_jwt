const express = require ('express');
const router = express.Router();
const bodyParser = require ('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require ('bcryptjs');
const config = require('../config');
const User = require('./userSchema');
const nodemailer = require('nodemailer');

const RESET_PASSWORD_SECRET = 'secret_key';

router.use(bodyParser.urlencoded({extended:true}));
router.use(bodyParser.json())

//get all users
router.get('/users',(req,res)=>{
    User.find({},(err,data)=>{
        if(err) throw err;
        res.send(data)
    })
})
//register User
router.post('/register',(req,res)=>{
    var hashpassword = bcrypt.hashSync(req.body.password,8)
    User.create({
        name:req.body.name,
        password:hashpassword,
        email:req.body.email,
        role:req.body.role?req.body.role:'User'

    },(err,user) => {
        if(err) return res.status(500).send('Error')
        res.status(200).json({ message:'Register Success'});
       
        

    })
})
//login user
router.post('/login',(req,res)=>{
    User.findOne ({email:req.body.email},(err,user)=>{
        if(err) return res.status(500).send('Error While Login')
        if(!user) return res.status(500).send({auth:false,token:'No User Found! Register First'});
        else{
            const passIsValid = bcrypt.compareSync(req.body.password, user.password)
         if (!passIsValid) return res.status(500).send({auth:false,token:'Invalid password'});
         //in case password match generate token
         var token = jwt.sign({id:user._id}, config.secert, {expiresIn:86400})
         res.send({auth:true,token:token})

        }


    })
})

//profile
router.get('/userInfo',(req,res) => {
    var token = req.headers ['x-access-token'];
    if(!token) return res.send({auth:false,token:'No Token Provided'});
    jwt.verify(token,config.secert,(err,user)=>{
        if(err) return res.send({auth:false,token:'Invalid Token'});
        User.findById(user.id,(err,result)=>{
            res.send(result)
        })
    })

})

router.post('/forgotpassword', async (req, res) => {
    const { email } = req.body;

    try {
        // Check if the user exists
        const user = await User.findOne({ email });
        if (!user) return res.status(404).send('User not found');

        // Generate a reset token (valid for 1 hour)
        const resetToken = jwt.sign({ id: user._id }, RESET_PASSWORD_SECRET, { expiresIn: '1h' });

        // Send email with reset link
        const transporter = nodemailer.createTransport({
            service: 'gmail', // Replace with your email service
            auth: {
                user: 'santanupaikaray1996@gmail.com',
                pass: 'nkts worg nitr cjom', 
            },
        });

        const resetLink = `https://fastidious-lolly-a51f0f.netlify.app/resetpassword?token=${resetToken}`;
        const mailOptions = {
            from: 'santanupaikaray1996@gmail.com',
            to: email,
            subject: 'Password Reset',
            text: `Click on this link to reset your password: ${resetLink}`,
        };

        await transporter.sendMail(mailOptions);

        res.status(200).json({ message:'Password reset email sent successfully'});
    } catch (err) {
        console.error(err);
        res.status(500).json({message:'Internal Server Error'});
    }
});

router.post('/resetpassword', async (req, res) => {
    const { token, newPassword } = req.body;

    try {
        const decoded = jwt.verify(token, RESET_PASSWORD_SECRET);
        const user = await User.findById(decoded.id);
        if (!user) return res.status(404).json({ message: 'User not found' });

        // Hash the new password and save it
        user.password = bcrypt.hashSync(newPassword, 8);
        await user.save();

        res.status(200).json({ message: 'Password reset successful' });
    } catch (err) {
        console.error(err);
        if (err.name === 'TokenExpiredError') {
            return res.status(400).json({ message: 'Reset token has expired' });
        }
        res.status(400).json({ message: 'Invalid token' });
    }
});


module.exports = router
