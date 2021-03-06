/*
 * Copyright (c) 2021 Michael Morris. All Rights Reserved.
 *
 * Licensed under the MIT license (the "License"). You may not use this file except in compliance
 * with the License. A copy of the License is located at
 *
 * https://github.com/mmmorris1975/aws-runas/blob/master/LICENSE
 *
 * or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License
 * for the specific language governing permissions and limitations under the License.
 */

const advancedIamFields = ['source-profile', 'external-id'];
const advancedSamlFields = ['auth-url', 'username', 'password', 'jump-role'];
const advancedOidcFields = ['client-id', 'redirect-uri'];

document.body.onload = function () {
	updateAdvancedForm(document.getElementById("adv-type").selectedOptions, document.getElementById("source-profile").value);
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
				show_alert("Error", this.responseText);
			}
		}
	};
	
	xhr.open("GET", "{{.roles_ep}}");
	xhr.send();
	return false;
})

roleList.onchange = postProfile;
function postProfile() {
	let roles = document.getElementById("roles");
	let profile = roles.selectedOptions[0].value;
	const xhr = new XMLHttpRequest();

	xhr.onreadystatechange = function () {
		if (this.readyState === 4) {
			document.getElementById("roles").value = profile;

			if (this.status === 200) {
				// data is empty, and message element doesn't exist
				// maybe we should just kill this? we can only know the AWS STS cred expiration, but I can already
				// imagine people asking to display saml/oidc cred expiration, which we won't (can't?) do
				// it was originally meant to show folks the approx time when mfa would be needed again, and that is
				// now unknowable if the profile uses external auth.
				//let data = this.responseText;
				//document.getElementById("message").innerHTML = "Credentials will expire on <i>" + data + "</i>"

				let o = JSON.parse(this.responseText);

				if (o.client_id !== "") {
					document.getElementById("adv-type").value = "oidc";
				} else if (o.auth_url !== "") {
					document.getElementById("adv-type").value = "saml";
				} else {
					document.getElementById("adv-type").value = "iam";
				}

				updateAdvancedForm(document.getElementById("adv-type").selectedOptions, o.source_profile);

				document.getElementById("role-arn").value = o.role_arn;
				document.getElementById("source-profile").value = o.source_profile;
				document.getElementById("external-id").value = o.external_id;
				document.getElementById("auth-url").value = o.auth_url;
				document.getElementById("username").value = o.username;
				document.getElementById("jump-role").value = o.jump_role;
				document.getElementById("client-id").value = o.client_id;
				document.getElementById("redirect-uri").value = o.redirect_uri;
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
				show_alert("Error", this.responseText);
			}
		}
	};
	
	xhr.open("POST", "{{.profile_ep}}");
	xhr.send(profile);
	return false
}

document.getElementById("refresh").addEventListener("click", function () {
	const xhr = new XMLHttpRequest();
	xhr.onreadystatechange = function () {
		if (this.readyState === 4) {
			if (this.status === 200) {
				postProfile()
			} else {
				console.log("refresh returned " + this.status + ": " + this.responseText);
			}
		}
	}

	xhr.open("POST", "{{.refresh_ep}}");
	xhr.send();
	return false
})

let advType = document.getElementById("adv-type")
advType.addEventListener("change", function () {
	updateAdvancedForm(this.selectedOptions, document.getElementById("source-profile").value);
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
				show_alert("Error", this.responseText);
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
				show_alert("Error", this.responseText);
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
adv_form.addEventListener("submit", function(evt) {
	evt.preventDefault();

	const xhr = new XMLHttpRequest();
	xhr.onreadystatechange = function () {
		if (this.readyState === 4) {
			if (this.status === 200) {
				// todo - anything?
				show_alert("Success", "running configuration updated");
			} else {
				console.log("advanced form POST returned " + this.status + ": " + this.responseText);
				show_alert("Error", this.responseText);
			}
		}
	};

	xhr.open("POST", "{{.custom_ep}}");
	xhr.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');

	let data = new URLSearchParams(new FormData(adv_form));
	xhr.send(data.toString());
	return false;
});

document.getElementById("save-as").addEventListener("click", function() {
	document.getElementById("profile-modal").style.display = 'block';
	document.getElementById("profile-name").focus();
});

document.getElementById("profile-form").addEventListener("submit", function(evt) {
	evt.preventDefault();

	const xhr = new XMLHttpRequest();
	xhr.onreadystatechange = function () {
		if (this.readyState === 4) {
			document.getElementById("profile-modal").style.display = 'none';

			if (this.status === 200) {
				show_alert("Success");
			} else {
				console.log("advanced form PUT returned " + this.status + ": " + this.responseText);
				show_alert("Error", this.responseText);
			}
		}
	};

	xhr.open("PUT", "{{.custom_ep}}");
	xhr.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');

	let data = new URLSearchParams(new FormData(adv_form));
	data.append("profile-name", document.getElementById("profile-name").value);

	xhr.send(data.toString());
	return false;
});

document.getElementById("profile-close").addEventListener("click", function () {
	document.getElementById("profile-modal").style.display = "none";
});

document.getElementById("alert-close").addEventListener("click", function () {
	this.parentElement.style.display='none';
});

function updateAdvancedForm(obj, val) {
	const xhr = new XMLHttpRequest();
	xhr.onreadystatechange = function () {
		if (this.readyState === 4) {
			let sel = document.getElementById("source-profile");
			sel.length = 1;
	
			if (this.status === 200) {
				JSON.parse(this.responseText).sort().forEach(function (val, idx, _) {
					if (val !== "default") {
						sel.add(new Option(val));
					}
				});
				sel.value = val;
			} else {
				console.log("list-profiles returned " + this.status + ": " + this.responseText);
				show_alert("Error", this.responseText);
			}
		}
	};

	xhr.open("GET", "{{.profiles_ep}}");
	xhr.send();

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

function show_alert(type, msg) {
	tmout = 4000;

	alertBox = document.getElementById('alerts')
	alertType = document.getElementById('alert-type');
	alertBox.classList.remove("w3-red", "w3-green");
	if (type.toLowerCase() === "success") {
		alertBox.classList.add("w3-green");
		alertType.textContent = "Success";
		tmout = 1500;
	} else {
		alertBox.classList.add("w3-red");
		alertType.textContent = "Error";
	}

	document.getElementById('alert-text').textContent = msg;
	alertBox.style.display = "inline";

	setTimeout(function () {alertBox.style.display = "none"}, tmout);
}