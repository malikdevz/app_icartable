Array.from(document.querySelectorAll("#copycode")).forEach((elem)=>{
    elem.addEventListener('click', function(){
        let btn_inner=elem.innerHTML;
        navigator.clipboard.writeText(elem.getAttribute('user_id'))
        elem.textContent="Copie Ok!"
        setTimeout(()=>{
            elem.innerHTML=btn_inner;
        },2000)
    })
    
})


Array.from(document.querySelectorAll('#show_pwd')).forEach((elem)=>{
    elem.addEventListener("click", function(){
        if(elem.checked){
            Array.from(document.querySelectorAll('input[name=password], input[name=confirm_pass]')).forEach((elem)=>{
                elem.setAttribute("type","text")
            })

        }else{
           Array.from(document.querySelectorAll('input[name=password], input[name=confirm_pass]')).forEach((elem)=>{
                elem.setAttribute("type","password")
            })
        }
    })
})