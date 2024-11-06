const User=require('../models/userModel')
const bcrypt=require('bcrypt')
const jwt=require('jsonwebtoken')
const createToken=(_id)=>{
    return jwt.sign({_id},process.env.SECRET,{expiresIn:'5d'})
}
//log in 
const logIn=async(req,res)=>{
    const{email,password}=req.body

    try{
        const user=await User.findOne({email})
        if(user){
          const match=await bcrypt.compare(password,user.password)
         if(match){
          const token=createToken(user._id)
          res.status(200).json({email,token})
         }
         else{
          return res.status(401).json({ error: 'Incorrect password' });

         }
        }

        else {
          // User not found
          return res.status(404).json({ error: 'User not found' });
        }

    }catch (error) {
      
    res.status(500).json({error: 'Something went wrong during login'})
  }
}

//signUp
const signUp=async(req,res)=>{
    const{email,password}=req.body
   try{
    const userExists=await User.findOne({email})
    if(userExists){
        throw Error('Email already in use')
    }
    const salt=await bcrypt.genSalt(10)
    const hash=await bcrypt.hash(password,salt)
    const user=await User.create({email,password:hash})
    const token=createToken(user._id)
    res.status(200).json({email,token})


   } 
   catch (error) {
    res.status(400).json({error: error.message})
  }

}
module.exports={logIn,signUp}