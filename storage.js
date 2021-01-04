/*
A wrapper that simplifies using object storage services.
+ Also supports using a local folder.


Packages required:
+ aws-sdk
+ mime
+ got
+ crypto (inbuilt)
+ path (inbuilt)
+ fs-extra
+ glob

*/


/********************************************* SETUP FUNCTIONS **********************************************/


//Load required packages.
const aws = require("aws-sdk")
const mime = require("mime")
const fetch = require("got")
const crypto = require("crypto")
const pathLib = require("path")
const fs = require("fs-extra")
const glob = require("glob")


//Export primary function.
module.exports = Storage
module.exports.B2 = B2
module.exports.cleanFileName = cleanFileName





/********************************************* PRIMARY FUNCTIONS **********************************************/


/*
The storage wrapper.
*/
function Storage(service = process.env.STORAGE_SERVICE, options = {}) {
  if(!(this instanceof Storage)) { return new Storage(...arguments) }

  //Validate options.
  service = String(service).toLowerCase().replace(/ /g, "")
  if(!["aws", "spaces", "s3", "b2", "folder"].includes(service)) { throw new Error("No such storage service. Valid options are aws, spaces, s3, b2 & folder.") }

  var actualService = "s3"
  if(service == "aws") {
    if(!options.region) { options.region = "us-east-2" }
  }
  else if(service == "spaces") {
    if(!options.region) { options.region = "nyc3" }
    if(!options.endpoint) { options.endpoint = "https://" + options.region + ".digitaloceanspaces.com" }
  }
  else if(service == "s3") {
    if(!options.endpoint) { throw new Error("Endpoint is required for custom S3 integrations.") }
  }
  else if(service == "b2") {
    var actualService = "b2"

    if(!options.key) { throw new Error("options.key is required for B2.") }
    if(!options.secret) { throw new Error("options.secret is required for B2.") }
  }
  else if(service == "folder") {
    var actualService = "folder"

    if(!options.directory) { throw new Error("options.directory is required for folder storage.") }
    options.directory = "/" + cleanFileName(options.directory) + "/"
  }

  //Create a client instance.
  if(actualService == "s3") {
    var client = new aws.S3({apiVersion: "2006-03-01", region: options.region, endpoint: options.endpoint, accessKeyId: options.key, secretAccessKey: options.secret})
  }
  else if(actualService == "b2") {
    var client = new B2({id: options.key, key: options.secret})
  }



  /*
  Uploads a file.
  */
  this.upload = async function(name, content, opts = {}) {
    name = cleanFileName(name)
    var type = mime.getType(name)

    if(actualService == "s3") {
      var acl = "private"
      if(opts.public) { acl = "public-read" }
      
      var result = await client.upload({ACL: acl, Key: name, Body: content, Bucket: opts.bucket || options.bucket, CacheControl: opts.cache || "max-age=3600", ContentType: type}).promise()
    }
    else if(actualService == "b2") {
      var result = await client.files.upload(name, content, opts.bucket || options.bucket, 0, type)
    }
    else if(actualService == "folder") {
      name = pathLib.join(options.directory, name)
      fs.ensureDirSync(pathLib.dirname(name))
      fs.writeFileSync(name, content)
    }

    return true
  }
  this.set = this.upload



  /*
  Downloads a file.
  */
  this.download = async function(name, opts = {}) {
    name = cleanFileName(name)

    if(actualService == "s3") {
      var result = await client.getObject({Key: name, Bucket: opts.bucket || options.bucket}).promise()
      return result.Body
    }
    else if(actualService == "b2") {
      return await client.files.download(name, opts.bucketName || options.bucketName)
    }
    else if(actualService == "folder") {
      return fs.readFileSync(pathLib.join(options.directory, name))
    }

  }
  this.get = this.download



  /*
  Creates a download URL.
  */
  this.downloadURL = async function(name, opts = {}) {
    name = cleanFileName(name)

    if(actualService == "s3") {
      return client.getSignedUrl("getObject", {Key: name, Bucket: opts.bucket || options.bucket, Expires: opts.maxSeconds || 900})
    }
    else if(actualService == "b2") {
      return await client.files.downloadURL(name, opts.maxSeconds || 900, opts.bucket || options.bucket, opts.bucketName || options.bucketName)
    }

    return undefined
  }



  /*
  Deletes a file.
  */
  this.delete = async function(names, opts = {}) {
    if(typeof names !== "object") { names = [names] }

    if(actualService == "s3") {
      var params = {Delete: {Objects: []}, Bucket: opts.bucket || options.bucket}

      for(var i in names) { params.Delete.Objects.push({Key: cleanFileName(names[i])}) }
      var result = await client.deleteObjects(params).promise()
    }
    else if(actualService == "b2") {
      for(var i in names) {
        await client.files.delete(names[i], null, opts.bucket || options.bucket)
      }
    }
    else if(actualService == "folder") {
      for(var i in names) {
        fs.unlinkSync(pathLib.join(options.directory, names[i]))
      }
    }

    return true
  }



  /*
  Lists files.
  */
  this.list = async function(prefix, opts = {}) {
    if(prefix) { prefix = prefix.replace(/^\//g, "") }
    var result = []

    if(actualService == "s3") {
      var files = await client.listObjects({MaxKeys: 1000, Prefix: prefix, Marker: opts.startFrom, Bucket: opts.bucket || options.bucket}).promise()

      //Beautify result.
      for(var i in files.Contents) {
        var file = files.Contents[i]
        result.push({name: file.Key, size: file.Size, etag: file.ETag, modified: file.LastModified})
      }

      //Load any left over files.
      if(files.IsTruncated) { result.push(await this.list(prefix, Object.assign({}, opts, {startFrom: files.NextMarker}))) }
    }
    else if(actualService == "b2") {
      var files = await client.files.list(prefix, opts.bucket || options.bucket)

      //Beautify result.
      for(var i in files) {
        var file = files[i]
        result.push({name: file.fileName, size: file.contentLength, etag: file.contentSha1, modified: file.uploadTimestamp})
      }
    }
    else if(actualService == "folder") {
      var files = glob.sync(pathLib.join(options.directory, prefix || "", "/**/*"))

      //Beautify result.
      for(var i in files) {
        if(fs.lstatSync(files[i]).isDirectory()) { continue }
        var file = files[i], stats = fs.statSync(file)
        result.push({name: file.replace(options.directory, ""), size: stats.size, modified: stats.mtime})
      }
    }

    return result
  }


  this.__proto__.client = client
}





/********************************************* B2 FUNCTIONS **********************************************/


/*
The B2 wrapper.
*/
function B2(options = {}) {
  if(!(this instanceof B2)) { return new B2(options || {}) }
  var b2 = this, fetchOpts = {json: true, timeout: 15000}, key = "", keyCreated = 0, downloadURL = ""


  /*
  Gets an auth key for operations.
  */
  var getAuth = async function() {
    if(key && keyCreated && keyCreated >= (time() - 86400)) { return true }

    var res = (await fetch("https://api.backblazeb2.com/b2api/v2/b2_authorize_account", Object.assign({}, fetchOpts, {baseUrl: null, auth: options.id + ":" + options.key}))).body
    b2.setAuth(res.authorizationToken, res.apiUrl, res.downloadUrl)

    return true
  }
  b2.authenticate = getAuth



  /*
  Manually sets an auth key.
  */
  b2.setAuth = function(authKey, apiURL, dlURL, created) {
    key = authKey, fetchOpts.baseUrl = apiURL + "/b2api/v2", downloadURL = dlURL + "/file", keyCreated = created || time()

    return true
  }



  /*
  Creates a request to the B2 API.
  */
  var request = async function(endpoint = "/", method = "GET", body = null, query = null, type = "api", tries = 0) {
    //Get auth key.
    await getAuth()

    var opts = Object.assign({}, fetchOpts, {headers: {Authorization: key, "User-Agent": "DevStorage/1.0.0"}, query: query, method: method, body: body})
    if(type == "download") { opts.baseUrl = downloadURL, opts.json = false, opts.encoding = null }

    //Make the request.
    try {
      var res = (await fetch(endpoint, opts)).body
    }
    catch(e) {
      tries++
      if(tries >= 3) { throw e }
      var res = e.body, code = res.code, status = e.statusCode
      if(code == "bad_auth_token" || code == "expired_auth_token") {
        keyCreated = 0
        return await request(endpoint, method, body, type, tries)
      }
      else if(status == 429) {
        var wait = ((e.headers && parseFloat(e.headers["retry-after"])) || 1) * 1000
        await delay(wait)
        return await request(endpoint, method, body, type, tries)
      }
      else { throw e }
    }

    return res
  }
  b2.request = request



  b2.files = {}



  /*
  Uploads a file.
  */
  b2.files.upload = async function(name, content = "", bucket, tries = 0, type = false, sha1 = false) {
    name = cleanFileName(name), bucket = bucket || options.bucketID

    //First get an upload URL.
    var url = await request("b2_get_upload_url", "POST", {bucketId: bucket})

    //Then actually upload.
    try {
      var headers = {Authorization: url.authorizationToken, "User-Agent": "DevStorage/1.0.0"}
      if(!type) { type = mime.getType(name) || "application/octet-stream" }
      if(!sha1) { sha1 = crypto.createHash("sha1").update(content).digest("hex") }
      headers["X-Bz-File-Name"] = name
      headers["Content-Type"] = type
      headers["X-Bz-Content-Sha1"] = sha1

      var res = JSON.parse((await fetch(url.uploadUrl, Object.assign({}, fetchOpts, {headers: headers, method: "POST", body: content, json: false}))).body)
    }
    catch(e) {
      tries++
      if(tries >= 3) { throw e }
      var res = e.body, code = res.code, status = e.statusCode
      if(code == "bad_auth_token" || code == "expired_auth_token") {
        keyCreated = 0
        return await b2.files.upload(name, content, bucket, tries, type, sha1)
      }
      else if(status == 429 || code == "service_unavailable") {
        var wait = ((e.headers && parseFloat(e.headers["retry-after"])) || 0.5) * 1000
        await delay(wait)
        return await b2.files.upload(name, content, bucket, tries, type, sha1)
      }
      else { throw e }
    }

    return res
  }



  /*
  Downloads a file.
  */
  b2.files.download = async function(name, bucketName) {
    name = cleanFileName(name), bucketName = bucketName || options.bucketName
    await getAuth()

    var res = await request(bucketName + "/" + name + "?Authorization=" + key, "GET", null, null, "download")

    return res
  }



  /*
  Returns the public download URL (Without authentication).
  */
  b2.files.downloadURL = async function(name, maxSeconds, bucket, bucketName) {
    name = cleanFileName(name), bucket = options.bucket || bucket, bucketName = bucketName || options.bucketName

    var auth = await request("b2_get_download_authorization", "POST", {fileNamePrefix: name, validDurationInSeconds: maxSeconds || 900, bucketId: bucket})

    return downloadURL + "/" + bucketName + "/" + name + "?Authorization=" + auth.authorizationToken
  }



  /*
  Deletes a file.
  */
  b2.files.delete = async function(name, version, bucket) {
    name = cleanFileName(name), bucket = bucket || options.bucketID

    //First get versions to delete.
    if(version) { var versions = {files: [{fileName: name, fileId: version}]} }
    else {
      var versions = await request("b2_list_file_versions", "POST", {bucketId: bucket, prefix: name, maxFileCount: 10000})
    }

    for(var i in versions.files) {
      var file = versions.files[i]

      await request("b2_delete_file_version", "POST", {fileName: file.fileName, fileId: file.fileId})
    }

    return true
  }



  /*
  Lists all files.
  */
  b2.files.list = async function(prefix, bucket, startingFile) {
    if(prefix) { prefix = prefix.replace(/^\//g, "") }
    bucket = bucket || options.bucketID

    var result = await request("b2_list_file_names", "POST", {prefix: prefix, bucketId: bucket, maxFileCount: 10000, startFileName: startingFile})
    if(result.nextFileName) { result.files.push(await b2.files.list(prefix, bucket, result.nextFileName)) }

    return result.files
  }

}





/********************************************* HELPER FUNCTIONS **********************************************/


/*
Cleans a file name.
*/
function cleanFileName(name) {
  if(!name) { throw new Error("No file name specified.") }
  if(name[0] == "/") { name = name.substring(1) }
  name = name.replace(/\/\/$/, "/").replace(/\/$/, "")
  return encodeURI(name)
}



/*
Returns the current time in UNIX seconds.
*/
function time() {
  return Math.floor(new Date() / 1000)
}



/*
ES6 Async delay function.
*/
function delay(ms) {
  return new Promise(function(resolve) {
    setTimeout(resolve, ms)
  })
}
