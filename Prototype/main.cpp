#include <opencv2/imgcodecs.hpp>
#include <opencv2/highgui.hpp>
#include <opencv2/imgproc.hpp>
#include <opencv2/objdetect.hpp>
#include <iostream>

using namespace cv;
using namespace std;

// constant declarations
const string CASCADE_CLASSIFIER = "Resources/haarcascade_frontalface_default.xml";

// function declarations
string getInputFile();
int getFaces(string);

// Main
int main() 
{
	// Step 1: get input file from user
	string path = getInputFile();
	Mat img = imread(path);

	// Step 2: Facial Recognition: generate face image files, duplicate input image with face rectangles drawn
	getFaces(path);

	// TODO Step 3: do encryption stuff

	return 0;
}


// Step 1: get input file from user
// TODO:  add input validation
string getInputFile()
{
	string path;
	cout << "Enter input file, including extension (from Input folder):\n\t";
	cin >> path;
	path = "Input/" + path;
	return path;
}

// Step 2: detect faces, output face files and face outlines file
int getFaces(string inputPath)
{
	// Load facial recognition XML
	CascadeClassifier faceCascade;
	faceCascade.load(CASCADE_CLASSIFIER);

	// test for loaded xml file
	if (faceCascade.empty()) 
	{
		cout << "facial recognition XML file not loaded" << endl;
	}

	// initialize imag matrix from input path
	Mat img = imread(inputPath);

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
		string outputPath = ("Output/face" + to_string(i) + ".jpg");
		imwrite(outputPath, croppedImage);

		// draw rectangle around face in original image
		rectangle(img, faces[i].tl(), faces[i].br(), Scalar(0, 255, 0), 2);	
	}

	// output full image with overlayed rectangles
	imwrite("Output/detectedfaces.jpg", img);

	// show detected faces in a display window
	imshow("Display Window", img);
	waitKey(0);

	return 0;
}