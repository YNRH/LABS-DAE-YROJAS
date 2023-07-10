import axios from 'axios';

const API_URL = 'http://localhost:8000'

class AuthService{

    login(usuario,password){
        return axios
        .post(API_URL + "/api/token/",{
            username:usuario,
            password:password
        })
        .then(res=>{
            if(res.data){
                let token = res.data.access;
                localStorage.setItem('token',token)
            }

            return res.data;
        })
    }
    
    verify(token){
        return axios.post(API_URL + "/api/verify/",{token:token})
        .then(res=>{
            if (res.status === 200) {
                return true
            }else{
                localStorage.removeItem('token');
                return false
            }
        }).catch((err)=>{
            console.log(err)
            localStorage.removeItem('token');
            return false
        })
    }

}

export default new AuthService();
