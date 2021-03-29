<?php
class Crypt3Des {
   public $key = "udik876ehjde32dU61edsxsf";//这个根据实际情况写
   function encrypt($input){//数据加密
    $str = $this->pkcs5_pad($input, 8);
	if (strlen($str) % 8) {
		$str = str_pad($str,strlen($str) + 8 - strlen($str) % 8, "\0");
	}
	$data=openssl_encrypt ($str, 'DES-EDE3' ,$key,OPENSSL_RAW_DATA | OPENSSL_NO_PADDING ,'');
    $data =  bin2hex($data);
	//$data = base64_encode($data);
    return $data;
   }
 
   function decrypt($encrypted){//数据解密
     $encrypted = pack("H*",$encrypted);
	// $encrypted = base64_decode($encrypted);
     $data=openssl_decrypt($encrypted,  'DES-EDE3' ,$key,OPENSSL_RAW_DATA | OPENSSL_NO_PADDING ,'');
     $y=$this->pkcs5_unpad($data);
     return $y;
   }
   function pkcs5_pad ($text, $blocksize) {
     $pad = $blocksize - (strlen($text) % $blocksize);
     return $text . str_repeat(chr($pad), $pad);
   }
   function pkcs5_unpad($text){
     $kes=strlen($text)-1;
     $pad = ord($text[$kes]);
     if ($pad > strlen($text)) {
        return false;
     }
     if (strspn($text, chr($pad), strlen($text) - $pad) != $pad){
        return false;
     }
     return substr($text, 0, -1 * $pad);
   }
 
   function PaddingPKCS7($data) {
     $block_size = @mcrypt_get_block_size(MCRYPT_3DES, MCRYPT_MODE_CBC);
     $padding_char = $block_size - (strlen($data) % $block_size);
     $data .= str_repeat(chr($padding_char),$padding_char);
     return $data;
   }
}
?>