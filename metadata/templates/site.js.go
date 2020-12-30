package templates

const SiteJs = `
const advancedIamFields = ['source-profile', 'external-id'];
const advancedSamlFields = ['auth-url', 'username', 'password', 'jump-role'];
const advancedOidcFields = ['client-id', 'redirect-uri'];

document.body.onload = function () {
	updateAdvancedForm(document.getElementById("adv-type").selectedOptions);
}

let roleList = document.getElementById("roles")
roleList.addEventListener("mousedown", function () {
	// I have tried about 10 different ways to rebuild the option list, 
	// and this is the only way which behaves consistently.
	const xhr = new XMLHttpRequest();

	xhr.onreadystatechange = function () {
		if (this.readyState === 4) {
			let sel = document.getElementById("roles");
			sel.length = 1;
	
			if (this.status === 200) {
				JSON.parse(this.responseText).sort().forEach(function (val, idx, _) {
					sel.add(new Option(val));
				});
			} else {
				console.log("list-roles returned " + this.status + ": " + this.responseText);
			}
		}
	};
	
	xhr.open("GET", "{{.roles_ep}}");
	xhr.send();
	return false;
})

roleList.addEventListener("change", function () {
	const profile = this.selectedOptions[0].value;
	const xhr = new XMLHttpRequest();

	xhr.onreadystatechange = function () {
		if (this.readyState === 4) {
			if (this.status === 200) {
				// data is empty, and message element doesn't exist
				// maybe we should just kill this? we can only know the AWS STS cred expiration, but I can already
				// imagine people asking to display saml/oidc cred expiration, which we won't (can't?) do
				// it was originally meant to show folks the approx time when mfa would be needed again, and that is
				// now unknowable if the profile uses external auth.
				//let data = this.responseText;
				//document.getElementById("message").innerHTML = "Credentials will expire on <i>" + data + "</i>"

				document.getElementById("roles").value = profile;
			} else if (this.status === 401) {
				let o = JSON.parse(this.responseText);
				if (o.username || o.username === "") {
					let elems = document.getElementById("cred-form").elements;
					elems["username"].value = o.username;

					document.getElementById("cred-modal").style.display = 'block';

					elems["username"].focus();
					if (o.username.length > 0) {
						elems["password"].focus();
					}
				} else {
					document.getElementById("mfa-modal").style.display = 'block';
					document.getElementById("mfa").focus();
				}
			} else {
				console.log("profile POST returned " + this.status + ": " + this.responseText);
			}
		}
	};
	
	xhr.open("POST", "{{.profile_ep}}");
	xhr.send(profile);
	return false
})

document.getElementById("refresh").addEventListener("click", function () {
    // todo - handle profile credential refresh
    // maybe this dies too? it can only ever handle AWS STS creds, and will never
    // refresh/handle an external auth provider session
})

let advType = document.getElementById("adv-type")
advType.addEventListener("change", function () {
	updateAdvancedForm(this.selectedOptions);
});

document.getElementById("mfa-close").addEventListener("click", function () {
	document.getElementById("mfa-modal").style.display = "none";
});

let mfa_form = document.getElementById('mfa-form');
mfa_form.addEventListener('submit', function (evt) {
	evt.preventDefault();

	const xhr = new XMLHttpRequest();
	xhr.onreadystatechange = function () {
		if (this.readyState === 4) {
			if (this.status === 200) {
				document.getElementById("mfa-modal").style.display = 'none';
                document.getElementById("mfa").value = "";
			} else if (this.status === 401) {
				document.getElementById("mfa-message").innerText = "Invalid MFA Code";
                document.getElementById("mfa").value = "";
                document.getElementById("mfa").focus();
                console.log(this.responseText);
			} else {
				console.log("mfa POST returned " + this.status + ": " + this.responseText);
			}
		}
	};

	xhr.open("POST", "{{.mfa_ep}}");
	xhr.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');

	let data = new URLSearchParams(new FormData(mfa_form));
	xhr.send(data.toString());
	return false;
});

document.getElementById("cred-close").addEventListener("click", function () {
	document.getElementById("cred-modal").style.display = "none";
});

let cred_form = document.getElementById('cred-form'); 
cred_form.addEventListener('submit', function (evt) {
	evt.preventDefault();

	const xhr = new XMLHttpRequest();
	xhr.onreadystatechange = function () {
		if (this.readyState === 4) {
			let elems = document.getElementById("cred-form").elements;
			elems["username"].value = "";
			elems["password"].value = "";

			if (this.status === 200) {
				document.getElementById("cred-modal").style.display = 'none';
			} else if (this.status === 401) {
				document.getElementById("login-message").innerText = "Invalid Credentials";
                console.log(this.responseText);
			} else {
				console.log("auth POST returned " + this.status + ": " + this.responseText);
			}
		}
	};

	xhr.open("POST", "{{.auth_ep}}");
	xhr.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');

	let data = new URLSearchParams(new FormData(cred_form));
	xhr.send(data.toString());
	return false;
});

let resetBtn = document.getElementById("reset")
resetBtn.addEventListener("click", function () {
    for (let e of advancedIamFields.concat(advancedSamlFields, advancedOidcFields, "role-arn")) {
        document.getElementById(e).value = "";
    }
})

let acc = document.getElementsByClassName("accordion")[0]
acc.addEventListener("click", function () {
    this.classList.toggle("active");

    let panel = document.getElementById("advanced-form")
    if (panel.style.display === "block") {
        panel.style.display = "none";
    } else {
        panel.style.display = "block";
    }
});

let adv_form = document.getElementById('role-form');
adv_form.addEventListener("submit", function() {
	evt.preventDefault();

	const xhr = new XMLHttpRequest();
	xhr.onreadystatechange = function () {
		if (this.readyState === 4) {
			if (this.status === 200) {
				
			} else {
				console.log("advanced form POST returned " + this.status + ": " + this.responseText);
			}
		}
	};

	xhr.open("POST", "{{.auth_ep}}");
	xhr.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');

	let data = new URLSearchParams(new FormData(adv_form));
	xhr.send(data.toString());
	return false;
});

document.getElementById("info").addEventListener("click", function() {
	const xhr = new XMLHttpRequest();
	xhr.onreadystatechange = function () {
		if (this.readyState === 4) {
			if (this.status === 200) {
				
			} else {
				console.log("advanced form GET returned " + this.status + ": " + this.responseText);
			}
		}
	};

	xhr.open("GET", "{{.auth_ep}}");
});

document.getElementById("save-as").addEventListener("click", function() {
	const xhr = new XMLHttpRequest();
	xhr.onreadystatechange = function () {
		if (this.readyState === 4) {
			if (this.status === 200) {
				
			} else {
				console.log("advanced form PUT returned " + this.status + ": " + this.responseText);
			}
		}
	};

	xhr.open("PUT", "{{.auth_ep}}");
	xhr.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');

	let data = new URLSearchParams(new FormData(adv_form));
	xhr.send(data.toString());
	return false;
});

function updateAdvancedForm(obj) {
    switch (obj[0].value) {
        case "saml":
            hide(advancedIamFields.concat(advancedOidcFields));
            show(advancedSamlFields);
            break;
        case "oidc":
            hide(advancedIamFields);
            show(advancedSamlFields.concat(advancedOidcFields));
            break;
        default:
            hide(advancedSamlFields.concat(advancedOidcFields));
            show(advancedIamFields);
    }
}

function hide(elems) {
    for (let e of elems) {
        document.getElementById(e + "-block").style.display = "none";
        document.getElementById(e).value = "";
    }
}

function show(elems) {
    for (let e of elems) {
        document.getElementById(e + "-block").style.display = "block";
    }
}
`
