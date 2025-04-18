pragma solidity >= 0.4.0 <= 0.9;

pragma experimental ABIEncoderV2;
//SmartContract solidity code
contract SmartContract {

    uint public fileCount = 0; 
    mapping(uint => file) public fileList; 
     struct file
     {
       string user;
       string filename;
       string sharing;
       string encrypted_keys;
       string date;       
     }
 
   // events 
   event fileCreated(uint indexed _fileId);

  
   //function  to save product details
   function createFile(string memory usr, string memory fname, string memory share, string memory ek, string memory dd) public {
      fileList[fileCount] = file(usr, fname, share, ek, dd);
      emit fileCreated(fileCount);
      fileCount++;
    }

     //get file count
    function getFileCount()  public view returns (uint) {
          return  fileCount;
    }

    function getUser(uint i) public view returns (string memory) {
        file memory chq = fileList[i];
	return chq.user;
    }

    function getFilename(uint i) public view returns (string memory) {
        file memory chq = fileList[i];
	return chq.filename;
    }

    function getSharing(uint i) public view returns (string memory) {
        file memory chq = fileList[i];
	return chq.sharing;
    }

    function getKeys(uint i) public view returns (string memory) {
        file memory chq = fileList[i];
	return chq.encrypted_keys;
    }

    function getDate(uint i) public view returns (string memory) {
        file memory chq = fileList[i];
	return chq.date;
    }

         
       
    uint public userCount = 0; 
    mapping(uint => user) public usersList; 
     struct user
     {
       string username;
       string password;
       string phone;
       string email;
       string user_address;
     }
 
   // events
 
   event userCreated(uint indexed _userId);
 
  function createUser(string memory _username, string memory _password, string memory _phone, string memory _email, string memory _address) public {
      usersList[userCount] = user(_username, _password, _phone, _email, _address);
      emit userCreated(userCount);
      userCount++;
    }

    
     //get user count
    function getUserCount()  public view returns (uint) {
          return  userCount;
    }

    function getUsername(uint i) public view returns (string memory) {
        user memory usr = usersList[i];
	return usr.username;
    }

    function getPassword(uint i) public view returns (string memory) {
        user memory usr = usersList[i];
	return usr.password;
    }

    function getAddress(uint i) public view returns (string memory) {
        user memory usr = usersList[i];
	return usr.user_address;
    }

    function getEmail(uint i) public view returns (string memory) {
        user memory usr = usersList[i];
	return usr.email;
    }

    function getPhone(uint i) public view returns (string memory) {
        user memory usr = usersList[i];
	return usr.phone;
    }
}