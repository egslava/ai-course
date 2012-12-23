
console.log("Piiiip");

function auth(user, password){
	$.ajax({
		type: "POST",
		url: "/auth",
		data: {
			user: user,
			password: password
		}
	}).done(function ( msg ) {
		$.jGrowl(msg);

		if (msg[0] == '0'){
			window.location = '/user/' + user;
		}
	})
}

function register(user, password){
	$.ajax({
		type: "POST",
		url: "/register",
		data: {
			user: user,
			password: password
		}
	}).done(function ( msg ) {
		$.jGrowl(msg);
	})
}

function logout(){
	console.log($.cookie('user'));
	$.removeCookie("user", {path: '/'});
	$.removeCookie("password", {path: '/'});
	window.location = '/';
}

function addNote(){
	var msg = $("#newmsg").val();
	var user = $.cookie('user');
	$.ajax({
		type: "POST",
		url: "/add",
		data: {
			title: msg
		}
	}).done(function ( msg ) {
		window.location.reload(1);
	})
}

//1. 
//При процедуре логина надо показать (если залогиниться не удаётся)
//хеш из базы и хеш, который мы сгенерировали из пароля

//2.
//Для каждой записи должен быть свой хеш. Если только что сгенерированный 
//хеш не совпадает с хешем из базы - вывести красный крести, иначе -
//зелёную галочку

