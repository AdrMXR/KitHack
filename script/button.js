$(document).ready(function(){
 
	$('.button-upp').click(function(){
		$('body, html').animate({
			scrollTop: '0px'
		}, 300);
	});
 
	$(window).scroll(function(){
		if( $(this).scrollTop() > 0 ){
			$('.button-upp').slideDown(300);
		} else {
			$('.button-upp').slideUp(300);
		}
	});
 
});