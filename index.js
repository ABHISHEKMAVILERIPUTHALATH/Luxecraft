import express from "express";
import axios from "axios";

const app=express()
const port=4000
app.get('/',(req,res)=>{
    res.send('localhost 4000')
})
app.get("/sample",(req,res)=>{
    res.json({message:'send success fully'})
})
app.listen(port,()=>{
console.log(`listening to ${port}`);
}
)