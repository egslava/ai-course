module source.app;
import vibe.d;
//import sass;
import std.process;
import source.sha256;
import std.stdio;

/**
 * Main page
 * If user is not logged in yet, page'll suggest to user
 * log in (/sign_in) or create account (/new_user)
 * if user is already logged in, it'll redirect him to /profile page
 *
 * On the profile page, there are one links:
 * 1. Create note (/new_note)
 * 2. Sign out link (/sign_out)
 * 3. List of notes 
 * 4. Link "remove note" opposite note (/remove_note command)
*/

MongoDB db;
MongoCollection userNotes;

bool userExists(string userName){
	return userNotes.count(["user": userName]) != 0;
}

bool auth(string userName, string password){
	return userNotes.count(["user": userName, "password": hex256(password)]) > 0;
}

bool auth(HttpServerRequest req){
	if (! ("user" in req.cookies))
		return false;
	if (! ("password" in req.cookies))
		return false;
	return auth(req.cookies["user"], req.cookies["password"]);
}

auto register_description=[
	"0 user has been successfully registred",
	"1 user with this username is already exists"
	];
int register(string userName, string password){
	if (auth (userName, password))
		return 1;
	userNotes.insert( ["user": userName, "password": hex256(password)]);

	return 0;
}

// get("/auth")
void web_auth(HttpServerRequest req, HttpServerResponse res){
	string u = req.form["user"];
	string p = req.form["password"];

	writeln("user: ", u, "password", p);
	if(userExists(u)){
		if (!auth(u, p)){
			res.writeBody("1 Invalid password", "text/plain");
			return;
		}
		res.setCookie("user", u);
		res.setCookie("password", p);
		res.writeBody("0 OK", "text/plain");
		writeln("We are not here");
		return;
	}

	res.writeBody("2 User is not exist");
}

// get("/register")
void web_register(HttpServerRequest req, HttpServerResponse res){
	string user = req.form["user"];
	string password = req.form["password"];
	int regCode = register(user, password);
	res.writeBody(
		register_description[regCode],
		"text/plain"
	);

	if(!regCode){
		res.setCookie("user", user);
		res.setCookie("password", password);
	}
}

void web_user(HttpServerRequest req, HttpServerResponse res){
	if (!auth(req)){
		res.redirect("/");
		return;
	}
	auto username = req.params["user"];
	auto notes = userNotes.findOne(["user": username]);
	res.render!("user.dt", notes);
}

// get("/")
void web_index(HttpServerRequest req, HttpServerResponse res){
	if (auth(req)){
		res.redirect("/user/"~req.cookies["user"]);
		return;
	}

	auto pageTitle = "Жесть, это просто магия шаблонов! :)";
	
	auto notes = userNotes.find(["user": "egslava"]);

	if ("user" in req.cookies)
		pageTitle = req.cookies["user"];
	res.render!("index.dt");
}

void web_add(HttpServerRequest req, HttpServerResponse res){
	if (!auth(req)){
		res.redirect("/");
		return;
	}
	userNotes.update( ["user": req.cookies["user"]], [
			"$push": [
				"notes": ["title": req.form["title"]]
			]
	]);
	res.writeBody("0 OK");
}

static this()
{ 
	db = connectMongoDB("127.0.0.1");
	userNotes = db["test.usernotes"];
	system ("compass compile ./public/styles/compass");
	
	auto router = new UrlRouter;
	router.get("/", &web_index)
			.post("/auth", &web_auth)
			.post("/register", &web_register)
			.get("/user/:user", &web_user)
			.post("/add", &web_add)
			.get("*", serveStaticFiles("./public/"));

	auto settings = new HttpServerSettings;
	settings.port = 8080;

	listenHttp(settings, router);
    //logInfo("Edit source/app.d to start your project.");
}
