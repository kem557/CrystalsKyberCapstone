#include <opencv2/imgcodecs.hpp>
#include <opencv2/highgui.hpp>
#include <opencv2/imgproc.hpp>
#include <opencv2/objdetect.hpp>
#include <iostream>

using namespace cv;
using namespace std;

// FACE DETECTION //

	   // IMAGES ARE MATRICES: coordinates are (y,x); (0,0) is top left corner; y is distance from top
	   // (0,0) (0,1) (0,2)
	   // (1,0) (1,1) (1,2)
	   // (2,0) (2,1) (2,2)

int main() {

	// Load test photo
	string inputPath = "Input/scrubs.jpg";
	Mat img = imread(inputPath);

	// Load facial recognition XML
	CascadeClassifier faceCascade;
	faceCascade.load("Resources/haarcascade_frontalface_default.xml");

	if (faceCascade.empty()) {					// test for loaded xml file
		cout << "XML file not loaded" << endl;
	}

	vector<Rect> faces;
	faceCascade.detectMultiScale(img, faces, 1.1, 8);	// detect faces

	// for each detected face: save as separate image, draw rectangle 
	for (int i = 0; i < faces.size(); i++)
	{
		// Get dimensions for face
		int xLower = faces[i].tl().x;
		int xUpper = faces[i].br().x;
		int yLower = faces[i].br().y;
		int yUpper = faces[i].tl().y;

		Mat croppedImage = img(Range(yUpper, yLower), Range(xLower, xUpper));

		// build filepath, output each croppedImage to a separate file
		string outputPath = ("Output/croppedImage" + to_string(i) + ".jpg");
		imwrite(outputPath, croppedImage);


		rectangle(img, faces[i].tl(), faces[i].br(), Scalar(0, 255, 0), 2);	//draw rectangle around face
	}

	// output full image with overlayed rectangles
	imwrite("Output/detected.jpg", img);

	// display full image with overlayed rectangles in separate window
	imshow("Image Window", img);
	waitKey(0);
	destroyAllWindows();

	return 0;
}