<?php

class Paginator {

     private $_perPage;
     private $_instance;
     private $_page;
     private $_limit;
     private $_totalRows = 0;

	public function __construct($perPage,$instance) {
		$this->_instance = $instance;
		$this->_perPage = $perPage;
		$this->set_instance();
	}

     private function get_start() {
          return ($this->_page * $this->_perPage) - $this->_perPage;
     }

     private function set_instance(){
          $this->_page = (int) (!isset($_GET[$this->_instance]) ? 1 : $_GET[$this->_instance]);
          $this->_page = ($this->_page == 0 ? 1 : $this->_page);
     }

     public function set_total($_totalRows){
          $this->_totalRows = $_totalRows;
     }

     public function get_limit(){
          return "LIMIT ".$this->get_start().",$this->_perPage";
     }

     public function page_links($path='?',$ext=null) {
          $adjacents = "2";
          $prev = $this->_page - 1;
          $next = $this->_page + 1;
          $lastpage = ceil($this->_totalRows/$this->_perPage);
          $lpm1 = $lastpage - 1;

          $pagination = "";

          if($lastpage > 1) {
               $pagination .= "<div class='pagination'>";

               if ($this->_page > 1) {
                    $pagination.= "<a href='".$path."$this->_instance=$prev"."$ext'><div class='circle'><i class='fa fa-angle-left previous'></i></div></a>";
               }else {
                    $pagination.= "<div class='disabled circle'><span class='disabled'><i class='fa fa-angle-left previous'></i></span></div>";
               }

               if ($lastpage < 7 + ($adjacents * 2)) {
                    for ($counter = 1; $counter <= $lastpage; $counter++) {
                         if ($counter == $this->_page) {
                              $pagination.= "<div class='circle current'><span class='current'>$counter</span></div>";
                         }else {
                              $pagination.= "<a href='".$path."$this->_instance=$counter"."$ext'><div class='circle'>$counter</div></a>";
                         }
                    }
               }elseif($lastpage > 5 + ($adjacents * 2)) {
                    if($this->_page < 1 + ($adjacents * 2)) {
                         for ($counter = 1; $counter < 4 + ($adjacents * 2); $counter++) {
                              if ($counter == $this->_page) {
                                   $pagination.= "<div class='circle current'><span class='current'>$counter</span></div>";
                              }else {
                                   $pagination.= "<a href='".$path."$this->_instance=$counter"."$ext'><div class='circle'>$counter</div></a>";
                              }
                         }
                         $pagination.= "...";
                         $pagination.= "<a href='".$path."$this->_instance=$lpm1"."$ext'><div class='circle'>$lpm1</div></a>";
                         $pagination.= "<a href='".$path."$this->_instance=$lastpage"."$ext'><div class='circle'>$lastpage</div></a>";

                    }elseif($lastpage - ($adjacents * 2) > $this->_page && $this->_page > ($adjacents * 2)) {
                         $pagination.= "<a href='".$path."$this->_instance=1"."$ext'><div class='circle'>1</div></a>";
                         $pagination.= "<a href='".$path."$this->_instance=2"."$ext'><div class='circle'>2</div></a>";
                         $pagination.= "...";

                         for ($counter = $this->_page - $adjacents; $counter <= $this->_page + $adjacents; $counter++) {
                              if ($counter == $this->_page) {
                                   $pagination.= "<div class='circle current'><span class='current'>$counter</span></div>";
                              }else {
                                   $pagination.= "<a href='".$path."$this->_instance=$counter"."$ext'><div class='circle'>$counter</div></a>";
                              }
                              $pagination.= "..";
                              $pagination.= "<a href='".$path."$this->_instance=$lpm1"."$ext'><div class='circle'>$lpm1</div></a>";
                              $pagination.= "<a href='".$path."$this->_instance=$lastpage"."$ext'><div class='circle'>$lastpage</div></a>";
                         }
                    }else {
                         $pagination.= "<a href='".$path."$this->_instance=1"."$ext'><div class='circle'>1</div></a>";
                         $pagination.= "<a href='".$path."$this->_instance=2"."$ext'><div class='circle'>2</div></a>";
                         $pagination.= "..";
                         for ($counter = $lastpage - (2 + ($adjacents * 2)); $counter <= $lastpage; $counter++) {
                              if ($counter == $this->_page) {
                                   $pagination.= "<div class='circle current'><span class='current'>$counter</span></div>";
                              }else {
                                   $pagination.= "<a href='".$path."$this->_instance=$counter"."$ext'><div class='circle'>$counter</div></a>";
                              }
                         }
                    }
               }

               if ($this->_page < $counter - 1) {
                    $pagination.= "<a href='".$path."$this->_instance=$next"."$ext'><div class='circle'><span class='disabled' aria-hidden='true'><i class='fa fa-angle-right'></i></span></div></a>";
               }else {
                    $pagination.= "<div class='disabled circle'><span class='disabled' aria-hidden='true'><i class='fa fa-angle-right'></i></span></div>";
                    $pagination.= "</div>\n";
               }
          }

          return $pagination;
     }
}
